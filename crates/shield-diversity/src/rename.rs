use crate::error::Result;
use crate::seed::{DiversityDomain, SeedDeriver};
use nexora_shield_dex::RenameConfig;
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Clone, PartialEq, Eq)]
pub struct RenameVariant {
    seed: u64,
    fingerprint: [u8; 32],
}

impl RenameVariant {
    pub fn derive(seed: &SeedDeriver) -> Result<Self> {
        let rename_seed = seed.domain_u64(DiversityDomain::Rename)?;
        let mut hasher = Sha256::new();
        hasher.update(b"nexora-shield/rename-variant/v1");
        hasher.update(rename_seed.to_le_bytes());
        let fingerprint = hasher.finalize().into();
        Ok(Self {
            seed: rename_seed,
            fingerprint,
        })
    }

    #[must_use]
    pub fn apply_to(&self, base: &RenameConfig) -> RenameConfig {
        let mut config = base.clone();
        config.seed = self.seed;
        config
    }

    #[must_use]
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}

impl fmt::Debug for RenameVariant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenameVariant")
            .field("seed", &"[REDACTED]")
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}
