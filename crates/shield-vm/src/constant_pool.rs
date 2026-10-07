use crate::error::{Result, VmError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum VmConstant {
    Int(i32),
    String(String),
    Type(String),
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstantPool {
    values: Vec<VmConstant>,
}

impl ConstantPool {
    pub fn intern(&mut self, value: VmConstant) -> Result<u16> {
        if let Some(index) = self.values.iter().position(|current| current == &value) {
            return u16::try_from(index).map_err(|_| VmError::InvalidConstant(u16::MAX));
        }

        let index =
            u16::try_from(self.values.len()).map_err(|_| VmError::InvalidConstant(u16::MAX))?;
        self.values.push(value);
        Ok(index)
    }

    pub fn get(&self, index: u16) -> Result<&VmConstant> {
        self.values
            .get(usize::from(index))
            .ok_or(VmError::InvalidConstant(index))
    }

    #[must_use]
    pub fn values(&self) -> &[VmConstant] {
        &self.values
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        let encoded =
            serde_json::to_vec(&self.values).map_err(|error| VmError::MetadataEncoding(error.to_string()))?;
        Ok(Sha256::digest(encoded).into())
    }
}
