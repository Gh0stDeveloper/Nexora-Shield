use crate::error::{IntegrityError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

pub const SHA256_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sha256Digest(#[serde(with = "digest_hex")] pub [u8; SHA256_LEN]);

impl Sha256Digest {
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SHA256_LEN] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        hex_lower(&self.0)
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Sha256Digest").field(&self.to_hex()).finish()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl FromStr for Sha256Digest {
    type Err = IntegrityError;

    fn from_str(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.len() != SHA256_LEN * 2 {
            return Err(IntegrityError::InvalidDigest(format!(
                "SHA-256 must contain {} hexadecimal characters",
                SHA256_LEN * 2
            )));
        }
        let mut output = [0_u8; SHA256_LEN];
        for (index, slot) in output.iter_mut().enumerate() {
            let offset = index * 2;
            *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|_| IntegrityError::InvalidDigest("non-hexadecimal SHA-256".into()))?;
        }
        Ok(Self(output))
    }
}

pub(crate) fn hash_components<'a>(label: &[u8], components: impl IntoIterator<Item = &'a [u8]>) -> Sha256Digest {
    let mut hasher = Sha256::new();
    append(&mut hasher, label);
    for component in components {
        append(&mut hasher, component);
    }
    Sha256Digest(hasher.finalize().into())
}

fn append(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
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

mod digest_hex {
    use super::{hex_lower, SHA256_LEN};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; SHA256_LEN], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_lower(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; SHA256_LEN], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() != SHA256_LEN * 2 {
            return Err(serde::de::Error::custom("invalid SHA-256 length"));
        }
        let mut output = [0_u8; SHA256_LEN];
        for (index, slot) in output.iter_mut().enumerate() {
            let offset = index * 2;
            *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|_| serde::de::Error::custom("invalid SHA-256 hex"))?;
        }
        Ok(output)
    }
}
