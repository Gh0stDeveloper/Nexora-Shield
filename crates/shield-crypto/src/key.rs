use crate::error::{DataProtectionError, Result};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

pub const ROOT_SECRET_LEN: usize = 32;
pub const ITEM_ID_LEN: usize = 32;
pub const CONTENT_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

const CONTEXT_LABEL: &[u8] = b"NexoraShield:C:context:v1";
const DERIVE_LABEL: &[u8] = b"NexoraShield:C:derive:v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildIdentity {
    pub application_id: String,
    pub build_id: String,
}

impl BuildIdentity {
    pub fn new(application_id: impl Into<String>, build_id: impl Into<String>) -> Result<Self> {
        let application_id = application_id.into();
        let build_id = build_id.into();

        if application_id.trim().is_empty() {
            return Err(DataProtectionError::InvalidIdentity(
                "application_id must not be empty".into(),
            ));
        }
        if build_id.trim().is_empty() {
            return Err(DataProtectionError::InvalidIdentity(
                "build_id must not be empty".into(),
            ));
        }
        if application_id.as_bytes().contains(&0) || build_id.as_bytes().contains(&0) {
            return Err(DataProtectionError::InvalidIdentity(
                "identity values must not contain NUL".into(),
            ));
        }

        Ok(Self {
            application_id,
            build_id,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyDomain {
    String = 1,
    Constant = 2,
    Resource = 3,
    Metadata = 4,
    Generic = 255,
}

impl KeyDomain {
    #[must_use]
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::String => b"string",
            Self::Constant => b"constant",
            Self::Resource => b"resource",
            Self::Metadata => b"metadata",
            Self::Generic => b"generic",
        }
    }
}

#[derive(Clone)]
pub struct KeySchedule {
    root_secret: Zeroizing<[u8; ROOT_SECRET_LEN]>,
    identity: BuildIdentity,
    context_hash: [u8; 32],
}

impl fmt::Debug for KeySchedule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeySchedule")
            .field("identity", &self.identity)
            .field("context_hash", &hex_lower(&self.context_hash))
            .field("root_secret", &"[REDACTED]")
            .finish()
    }
}

impl KeySchedule {
    pub fn new(root_secret: &[u8], identity: BuildIdentity) -> Result<Self> {
        if root_secret.len() != ROOT_SECRET_LEN {
            return Err(DataProtectionError::InvalidRootSecretLength {
                actual: root_secret.len(),
            });
        }

        let mut secret = [0_u8; ROOT_SECRET_LEN];
        secret.copy_from_slice(root_secret);
        let context_hash = context_hash(&identity);

        Ok(Self {
            root_secret: Zeroizing::new(secret),
            identity,
            context_hash,
        })
    }

    #[must_use]
    pub fn identity(&self) -> &BuildIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn context_hash(&self) -> &[u8; 32] {
        &self.context_hash
    }

    #[must_use]
    pub fn context_fingerprint_hex(&self) -> String {
        hex_lower(&self.context_hash)
    }

    pub fn opaque_item_id(&self, domain: KeyDomain, logical_id: &str) -> Result<[u8; ITEM_ID_LEN]> {
        if logical_id.is_empty() || logical_id.as_bytes().contains(&0) {
            return Err(DataProtectionError::KeyDerivation(
                "logical identifier must be non-empty and contain no NUL".into(),
            ));
        }
        self.expand(domain, b"item-id", logical_id.as_bytes(), &[])
    }

    pub(crate) fn content_key(
        &self,
        domain: KeyDomain,
        item_id: &[u8; ITEM_ID_LEN],
    ) -> Result<Zeroizing<[u8; CONTENT_KEY_LEN]>> {
        self.expand(domain, b"content-key", item_id, &[])
            .map(Zeroizing::new)
    }

    pub(crate) fn nonce(
        &self,
        domain: KeyDomain,
        item_id: &[u8; ITEM_ID_LEN],
        plaintext_hash: &[u8; 32],
    ) -> Result<[u8; NONCE_LEN]> {
        self.expand(domain, b"nonce", item_id, plaintext_hash)
    }

    fn expand<const N: usize>(
        &self,
        domain: KeyDomain,
        purpose: &[u8],
        primary: &[u8],
        secondary: &[u8],
    ) -> Result<[u8; N]> {
        let hkdf = Hkdf::<Sha256>::new(Some(&self.context_hash), self.root_secret.as_ref());
        let mut info = Vec::with_capacity(
            DERIVE_LABEL.len()
                + domain.label().len()
                + purpose.len()
                + primary.len()
                + secondary.len()
                + 8,
        );
        append_component(&mut info, DERIVE_LABEL);
        append_component(&mut info, domain.label());
        append_component(&mut info, purpose);
        append_component(&mut info, primary);
        append_component(&mut info, secondary);

        let mut output = [0_u8; N];
        hkdf.expand(&info, &mut output).map_err(|_| {
            DataProtectionError::KeyDerivation("HKDF output length was rejected".into())
        })?;
        Ok(output)
    }
}

fn context_hash(identity: &BuildIdentity) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CONTEXT_LABEL);
    hasher.update([0]);
    hasher.update(identity.application_id.as_bytes());
    hasher.update([0]);
    hasher.update(identity.build_id.as_bytes());
    hasher.finalize().into()
}

fn append_component(output: &mut Vec<u8>, component: &[u8]) {
    output.extend_from_slice(&(component.len() as u64).to_le_bytes());
    output.extend_from_slice(component);
}

#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[must_use]
pub fn hex_lower(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(data.len() * 2);
    for byte in data {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
