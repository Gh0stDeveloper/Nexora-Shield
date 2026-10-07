use crate::error::{DiversityError, Result};
use crate::seed::{DiversityDomain, SeedDeriver};
use nexora_shield_native::GeneratedNativeData;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeConstantVariant {
    pub build_tag: [u8; 16],
    pub fingerprint: [u8; 32],
}

impl NativeConstantVariant {
    pub fn derive(seed: &SeedDeriver, build_id: &str) -> Result<(Self, GeneratedNativeData)> {
        if build_id.trim().is_empty() {
            return Err(DiversityError::EmptyBuildId);
        }
        let key = seed.domain_key(DiversityDomain::NativeConstants)?;
        let generated = GeneratedNativeData::derive(build_id, &key)
            .map_err(|error| DiversityError::Native(error.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(b"nexora-shield/native-variant/v1");
        hasher.update(generated.build_tag);
        for word in generated.words {
            hasher.update(word.to_le_bytes());
        }
        let fingerprint = hasher.finalize().into();

        Ok((
            Self {
                build_tag: generated.build_tag,
                fingerprint,
            },
            generated,
        ))
    }
}
