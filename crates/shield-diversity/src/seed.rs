use crate::error::{DiversityError, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateBuildSeed {
    bytes: Vec<u8>,
}

impl PrivateBuildSeed {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(DiversityError::EmptyPrivateSeed);
        }
        Ok(Self { bytes })
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for PrivateBuildSeed {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for PrivateBuildSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateBuildSeed")
            .field("bytes", &"[REDACTED]")
            .field("len", &self.bytes.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", content = "value", rename_all = "snake_case")]
pub enum DiversityMode {
    UniqueBuild { nonce: String },
    ReproduciblePrivate { reproduction_id: String },
}

impl DiversityMode {
    fn label(&self) -> &'static [u8] {
        match self {
            Self::UniqueBuild { .. } => b"unique-build",
            Self::ReproduciblePrivate { .. } => b"reproducible-private",
        }
    }

    fn value(&self) -> &str {
        match self {
            Self::UniqueBuild { nonce } => nonce,
            Self::ReproduciblePrivate { reproduction_id } => reproduction_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSeedContext {
    pub application_id: String,
    pub build_id: String,
    pub mode: DiversityMode,
}

impl BuildSeedContext {
    pub fn validate(&self) -> Result<()> {
        if self.application_id.trim().is_empty() {
            return Err(DiversityError::EmptyApplicationId);
        }
        if self.build_id.trim().is_empty() {
            return Err(DiversityError::EmptyBuildId);
        }
        if self.mode.value().trim().is_empty() {
            return Err(DiversityError::EmptyModeValue);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiversityDomain {
    Rename,
    PassOrder,
    Cfg,
    IntegrityTopology,
    StringPartition,
    VmMap,
    NativeConstants,
}

impl DiversityDomain {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Rename => b"rename",
            Self::PassOrder => b"pass-order",
            Self::Cfg => b"cfg",
            Self::IntegrityTopology => b"integrity-topology",
            Self::StringPartition => b"string-partition",
            Self::VmMap => b"vm-map",
            Self::NativeConstants => b"native-constants",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SeedDeriver {
    root: [u8; 32],
    context_fingerprint: [u8; 32],
}

impl SeedDeriver {
    pub fn derive(private_seed: &PrivateBuildSeed, context: &BuildSeedContext) -> Result<Self> {
        context.validate()?;

        let mut mac = HmacSha256::new_from_slice(private_seed.as_slice())
            .map_err(|error| DiversityError::Encoding(error.to_string()))?;
        update_component(&mut mac, b"nexora-shield/diversity-root/v1");
        update_component(&mut mac, context.application_id.as_bytes());
        update_component(&mut mac, context.build_id.as_bytes());
        update_component(&mut mac, context.mode.label());
        update_component(&mut mac, context.mode.value().as_bytes());
        let root: [u8; 32] = mac.finalize().into_bytes().into();

        let mut hasher = Sha256::new();
        hasher.update(b"nexora-shield/diversity-context/v1");
        hasher.update(context.application_id.as_bytes());
        hasher.update([0]);
        hasher.update(context.build_id.as_bytes());
        hasher.update([0]);
        hasher.update(context.mode.label());
        hasher.update([0]);
        hasher.update(context.mode.value().as_bytes());
        let context_fingerprint = hasher.finalize().into();

        Ok(Self {
            root,
            context_fingerprint,
        })
    }

    pub fn domain_key(&self, domain: DiversityDomain) -> Result<[u8; 32]> {
        let mut mac = HmacSha256::new_from_slice(&self.root)
            .map_err(|error| DiversityError::Encoding(error.to_string()))?;
        update_component(&mut mac, b"nexora-shield/diversity-domain/v1");
        update_component(&mut mac, domain.label());
        Ok(mac.finalize().into_bytes().into())
    }

    pub fn domain_u64(&self, domain: DiversityDomain) -> Result<u64> {
        let key = self.domain_key(domain)?;
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&key[..8]);
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn derive_u64(&self, domain: DiversityDomain, label: &[u8]) -> Result<u64> {
        let domain_key = self.domain_key(domain)?;
        let mut mac = HmacSha256::new_from_slice(&domain_key)
            .map_err(|error| DiversityError::Encoding(error.to_string()))?;
        update_component(&mut mac, b"nexora-shield/diversity-item/v1");
        update_component(&mut mac, label);
        let digest = mac.finalize().into_bytes();
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        Ok(u64::from_le_bytes(bytes))
    }

    #[must_use]
    pub const fn context_fingerprint(&self) -> [u8; 32] {
        self.context_fingerprint
    }
}

impl fmt::Debug for SeedDeriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SeedDeriver")
            .field("root", &"[REDACTED]")
            .field("context_fingerprint", &self.context_fingerprint)
            .finish()
    }
}

fn update_component(mac: &mut HmacSha256, value: &[u8]) {
    mac.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    mac.update(value);
}
