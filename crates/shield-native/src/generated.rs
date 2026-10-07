use crate::error::{NativeError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GENERATED_NATIVE_DATA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedNativeData {
    pub version: u32,
    pub build_tag: [u8; 16],
    pub words: [u64; 4],
}

impl GeneratedNativeData {
    pub fn derive(build_id: &str, private_seed: &[u8]) -> Result<Self> {
        if build_id.trim().is_empty() {
            return Err(NativeError::EmptyBuildId);
        }
        if private_seed.is_empty() {
            return Err(NativeError::EmptySeed);
        }

        let digest = derive_digest(build_id.as_bytes(), private_seed);
        let mut build_tag = [0_u8; 16];
        build_tag.copy_from_slice(&digest[..16]);

        let mut words = [0_u64; 4];
        for (index, slot) in words.iter_mut().enumerate() {
            let offset = index * 8;
            let mut word = [0_u8; 8];
            word.copy_from_slice(&digest[offset..offset + 8]);
            *slot = u64::from_le_bytes(word);
        }

        Ok(Self {
            version: GENERATED_NATIVE_DATA_VERSION,
            build_tag,
            words,
        })
    }
}

fn derive_digest(build_id: &[u8], private_seed: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    append(&mut hasher, b"nexora-shield/native-generated/v1");
    append(&mut hasher, build_id);
    append(&mut hasher, private_seed);
    hasher.finalize().into()
}

fn append(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}
