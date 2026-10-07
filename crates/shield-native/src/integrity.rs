use crate::error::{NativeError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const NATIVE_DIGEST_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NativeDigest(pub [u8; NATIVE_DIGEST_LEN]);

impl NativeDigest {
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    #[must_use]
    pub fn matches(self, bytes: &[u8]) -> bool {
        let observed = Self::of(bytes);
        bool::from(self.0.ct_eq(&observed.0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeRegion {
    pub label: String,
    pub expected: NativeDigest,
}

impl NativeRegion {
    pub fn new(label: impl Into<String>, bytes: &[u8]) -> Result<Self> {
        let label = label.into();
        if label.trim().is_empty() {
            return Err(NativeError::EmptyRegionLabel);
        }

        Ok(Self {
            label,
            expected: NativeDigest::of(bytes),
        })
    }

    #[must_use]
    pub fn verify(&self, bytes: &[u8]) -> NativeIntegrityCheck {
        let observed = NativeDigest::of(bytes);
        NativeIntegrityCheck {
            label: self.label.clone(),
            matched: bool::from(self.expected.0.ct_eq(&observed.0)),
            observed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeIntegrityCheck {
    pub label: String,
    pub matched: bool,
    pub observed: NativeDigest,
}
