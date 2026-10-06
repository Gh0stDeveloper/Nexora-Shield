use crate::error::{DataProtectionError, Result};
use crate::key::{sha256, KeyDomain, KeySchedule, ITEM_ID_LEN, NONCE_LEN};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

pub const CONTAINER_MAGIC: &[u8; 4] = b"NSC1";
pub const CONTAINER_VERSION: u8 = 1;
pub const CONTAINER_HEADER_LEN: usize = 4 + 1 + 1 + 2 + ITEM_ID_LEN + NONCE_LEN + 8 + 8;
pub const DEFAULT_MAX_PLAINTEXT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContainerKind {
    String = 1,
    Constant = 2,
    Resource = 3,
    Generic = 255,
}

impl ContainerKind {
    pub fn from_byte(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::String),
            2 => Ok(Self::Constant),
            3 => Ok(Self::Resource),
            255 => Ok(Self::Generic),
            other => Err(DataProtectionError::InvalidContainer(format!(
                "unknown container kind {other}"
            ))),
        }
    }

    #[must_use]
    pub const fn domain(self) -> KeyDomain {
        match self {
            Self::String => KeyDomain::String,
            Self::Constant => KeyDomain::Constant,
            Self::Resource => KeyDomain::Resource,
            Self::Generic => KeyDomain::Generic,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    pub version: u8,
    pub kind: ContainerKind,
    pub item_id: [u8; ITEM_ID_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub plaintext_len: u64,
    pub ciphertext_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedContainer<'a> {
    info: ContainerInfo,
    ciphertext: &'a [u8],
}

pub fn seal(
    schedule: &KeySchedule,
    kind: ContainerKind,
    logical_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let plaintext_len =
        u64::try_from(plaintext.len()).map_err(|_| DataProtectionError::SizeLimitExceeded {
            context: "plaintext".into(),
            size: u64::MAX,
            limit: DEFAULT_MAX_PLAINTEXT_BYTES,
        })?;
    if plaintext_len > DEFAULT_MAX_PLAINTEXT_BYTES {
        return Err(DataProtectionError::SizeLimitExceeded {
            context: "plaintext".into(),
            size: plaintext_len,
            limit: DEFAULT_MAX_PLAINTEXT_BYTES,
        });
    }

    let item_id = schedule.opaque_item_id(kind.domain(), logical_id)?;
    let key = schedule.content_key(kind.domain(), &item_id)?;
    let plaintext_hash = sha256(plaintext);
    let nonce = schedule.nonce(kind.domain(), &item_id, &plaintext_hash)?;
    let aad = associated_data(schedule, kind, &item_id, plaintext_len);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| DataProtectionError::AuthenticationFailed)?;

    serialize(kind, item_id, nonce, plaintext_len, &ciphertext)
}

pub fn open(
    schedule: &KeySchedule,
    expected_kind: ContainerKind,
    logical_id: &str,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    let parsed = parse(bytes, DEFAULT_MAX_PLAINTEXT_BYTES)?;
    if parsed.info.kind != expected_kind {
        return Err(DataProtectionError::KindMismatch {
            expected: expected_kind as u8,
            actual: parsed.info.kind as u8,
        });
    }

    let expected_id = schedule.opaque_item_id(expected_kind.domain(), logical_id)?;
    if parsed.info.item_id != expected_id {
        return Err(DataProtectionError::IdentifierMismatch);
    }

    let key = schedule.content_key(expected_kind.domain(), &expected_id)?;
    let aad = associated_data(
        schedule,
        expected_kind,
        &expected_id,
        parsed.info.plaintext_len,
    );
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&parsed.info.nonce),
            Payload {
                msg: parsed.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| DataProtectionError::AuthenticationFailed)?;

    if u64::try_from(plaintext.len()).ok() != Some(parsed.info.plaintext_len) {
        return Err(DataProtectionError::InvalidContainer(
            "decrypted length does not match authenticated header".into(),
        ));
    }

    Ok(plaintext)
}

pub fn inspect(bytes: &[u8]) -> Result<ContainerInfo> {
    parse(bytes, DEFAULT_MAX_PLAINTEXT_BYTES).map(|parsed| parsed.info)
}

fn serialize(
    kind: ContainerKind,
    item_id: [u8; ITEM_ID_LEN],
    nonce: [u8; NONCE_LEN],
    plaintext_len: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let ciphertext_len = u64::try_from(ciphertext.len()).map_err(|_| {
        DataProtectionError::InvalidContainer("ciphertext length does not fit u64".into())
    })?;
    let total = CONTAINER_HEADER_LEN
        .checked_add(ciphertext.len())
        .ok_or_else(|| DataProtectionError::InvalidContainer("container size overflow".into()))?;

    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(CONTAINER_MAGIC);
    output.push(CONTAINER_VERSION);
    output.push(kind as u8);
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&item_id);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&plaintext_len.to_le_bytes());
    output.extend_from_slice(&ciphertext_len.to_le_bytes());
    output.extend_from_slice(ciphertext);
    Ok(output)
}

fn parse(bytes: &[u8], max_plaintext: u64) -> Result<ParsedContainer<'_>> {
    if bytes.len() < CONTAINER_HEADER_LEN {
        return Err(DataProtectionError::InvalidContainer(
            "truncated container header".into(),
        ));
    }
    if &bytes[..4] != CONTAINER_MAGIC {
        return Err(DataProtectionError::InvalidContainer(
            "invalid container magic".into(),
        ));
    }

    let version = bytes[4];
    if version != CONTAINER_VERSION {
        return Err(DataProtectionError::UnsupportedVersion(version));
    }
    let kind = ContainerKind::from_byte(bytes[5])?;
    let reserved = u16::from_le_bytes([bytes[6], bytes[7]]);
    if reserved != 0 {
        return Err(DataProtectionError::InvalidContainer(
            "reserved header bits are non-zero".into(),
        ));
    }

    let mut item_id = [0_u8; ITEM_ID_LEN];
    item_id.copy_from_slice(&bytes[8..8 + ITEM_ID_LEN]);
    let nonce_start = 8 + ITEM_ID_LEN;
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[nonce_start..nonce_start + NONCE_LEN]);
    let lengths_start = nonce_start + NONCE_LEN;
    let plaintext_len = read_u64(bytes, lengths_start)?;
    let ciphertext_len = read_u64(bytes, lengths_start + 8)?;

    if plaintext_len > max_plaintext {
        return Err(DataProtectionError::SizeLimitExceeded {
            context: "container plaintext".into(),
            size: plaintext_len,
            limit: max_plaintext,
        });
    }

    let ciphertext_len_usize = usize::try_from(ciphertext_len).map_err(|_| {
        DataProtectionError::InvalidContainer("ciphertext length does not fit usize".into())
    })?;
    let expected_len = CONTAINER_HEADER_LEN
        .checked_add(ciphertext_len_usize)
        .ok_or_else(|| DataProtectionError::InvalidContainer("container size overflow".into()))?;
    if expected_len != bytes.len() {
        return Err(DataProtectionError::InvalidContainer(format!(
            "encoded ciphertext length {ciphertext_len} does not match file size {}",
            bytes.len()
        )));
    }
    if ciphertext_len < 16 {
        return Err(DataProtectionError::InvalidContainer(
            "ciphertext is shorter than the AEAD tag".into(),
        ));
    }

    Ok(ParsedContainer {
        info: ContainerInfo {
            version,
            kind,
            item_id,
            nonce,
            plaintext_len,
            ciphertext_len,
        },
        ciphertext: &bytes[CONTAINER_HEADER_LEN..],
    })
}

fn associated_data(
    schedule: &KeySchedule,
    kind: ContainerKind,
    item_id: &[u8; ITEM_ID_LEN],
    plaintext_len: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(4 + 1 + 1 + ITEM_ID_LEN + 32 + 8);
    aad.extend_from_slice(CONTAINER_MAGIC);
    aad.push(CONTAINER_VERSION);
    aad.push(kind as u8);
    aad.extend_from_slice(item_id);
    aad.extend_from_slice(schedule.context_hash());
    aad.extend_from_slice(&plaintext_len.to_le_bytes());
    aad
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| DataProtectionError::InvalidContainer("offset overflow".into()))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| DataProtectionError::InvalidContainer("truncated u64 field".into()))?;
    let mut array = [0_u8; 8];
    array.copy_from_slice(slice);
    Ok(u64::from_le_bytes(array))
}
