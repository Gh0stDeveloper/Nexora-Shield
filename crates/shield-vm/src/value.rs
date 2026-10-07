use crate::error::{Result, VmError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum VmValue {
    Int(i64),
    Ref(u64),
    Null,
    Void,
}

impl VmValue {
    pub fn as_int(&self) -> Result<i64> {
        match self {
            Self::Int(value) => Ok(*value),
            _ => Err(VmError::InvalidValueType("int")),
        }
    }
}
