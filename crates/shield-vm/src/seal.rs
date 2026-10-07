use crate::error::{Result, VmError};
use crate::ir::VmMethod;
use crate::opcode::OpcodeAllocation;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmMetadata {
    pub version: u32,
    pub method_idx: u32,
    pub register_count: u16,
    pub instruction_count: usize,
    pub handler_count: usize,
    pub constant_pool_digest: [u8; 32],
    pub opcode_fingerprint: [u8; 32],
}

impl VmMetadata {
    pub fn from_method(method: &VmMethod, allocation: &OpcodeAllocation) -> Result<Self> {
        Ok(Self {
            version: 1,
            method_idx: method.method_idx,
            register_count: method.register_count,
            instruction_count: method.instructions.len(),
            handler_count: method.handlers.len(),
            constant_pool_digest: method.constants.digest()?,
            opcode_fingerprint: allocation.fingerprint(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedMetadata {
    pub payload: Vec<u8>,
    pub tag: [u8; 32],
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MetadataSealer;

impl MetadataSealer {
    pub fn seal(metadata: &VmMetadata, key: &[u8]) -> Result<SealedMetadata> {
        if key.is_empty() {
            return Err(VmError::EmptySealKey);
        }
        let payload =
            serde_json::to_vec(metadata).map_err(|error| VmError::MetadataEncoding(error.to_string()))?;
        let tag = authenticate(&payload, key)?;
        Ok(SealedMetadata { payload, tag })
    }

    pub fn verify(sealed: &SealedMetadata, key: &[u8]) -> Result<VmMetadata> {
        if key.is_empty() {
            return Err(VmError::EmptySealKey);
        }
        let mut mac =
            HmacSha256::new_from_slice(key).map_err(|error| VmError::MetadataEncoding(error.to_string()))?;
        mac.update(b"nexora-shield/vm-metadata/v1");
        mac.update(&sealed.payload);
        mac.verify_slice(&sealed.tag)
            .map_err(|_| VmError::MetadataSealMismatch)?;
        serde_json::from_slice(&sealed.payload)
            .map_err(|error| VmError::MetadataEncoding(error.to_string()))
    }
}

fn authenticate(payload: &[u8], key: &[u8]) -> Result<[u8; 32]> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|error| VmError::MetadataEncoding(error.to_string()))?;
    mac.update(b"nexora-shield/vm-metadata/v1");
    mac.update(payload);
    Ok(mac.finalize().into_bytes().into())
}
