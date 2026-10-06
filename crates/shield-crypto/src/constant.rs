use crate::container::{open, seal, ContainerKind};
use crate::error::{DataProtectionError, Result};
use crate::key::KeySchedule;
use std::fmt;
use zeroize::Zeroize;

const TAG_BOOL: u8 = 1;
const TAG_I32: u8 = 2;
const TAG_I64: u8 = 3;
const TAG_F32: u8 = 4;
const TAG_F64: u8 = 5;
const TAG_BYTES: u8 = 6;

#[derive(Clone, PartialEq)]
pub enum ConstantValue {
    Bool(bool),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    Bytes(Vec<u8>),
}

impl fmt::Debug for ConstantValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Bool(_) => "bool",
            Self::I32(_) => "i32",
            Self::I64(_) => "i64",
            Self::F32(_) => "f32",
            Self::F64(_) => "f64",
            Self::Bytes(_) => "bytes",
        };
        formatter
            .debug_struct("ConstantValue")
            .field("kind", &kind)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ConstantValue {
    fn drop(&mut self) {
        match self {
            Self::Bool(value) => *value = false,
            Self::I32(value) => *value = 0,
            Self::I64(value) => *value = 0,
            Self::F32(value) => *value = 0.0,
            Self::F64(value) => *value = 0.0,
            Self::Bytes(value) => value.zeroize(),
        }
    }
}

pub fn protect_constant(
    schedule: &KeySchedule,
    logical_id: &str,
    value: &ConstantValue,
) -> Result<Vec<u8>> {
    seal(
        schedule,
        ContainerKind::Constant,
        logical_id,
        &encode(value)?,
    )
}

pub fn unprotect_constant(
    schedule: &KeySchedule,
    logical_id: &str,
    container: &[u8],
) -> Result<ConstantValue> {
    let bytes = open(schedule, ContainerKind::Constant, logical_id, container)?;
    decode(&bytes)
}

pub fn encode(value: &ConstantValue) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    match value {
        ConstantValue::Bool(value) => {
            output.push(TAG_BOOL);
            output.push(u8::from(*value));
        }
        ConstantValue::I32(value) => {
            output.push(TAG_I32);
            output.extend_from_slice(&value.to_le_bytes());
        }
        ConstantValue::I64(value) => {
            output.push(TAG_I64);
            output.extend_from_slice(&value.to_le_bytes());
        }
        ConstantValue::F32(value) => {
            output.push(TAG_F32);
            output.extend_from_slice(&value.to_bits().to_le_bytes());
        }
        ConstantValue::F64(value) => {
            output.push(TAG_F64);
            output.extend_from_slice(&value.to_bits().to_le_bytes());
        }
        ConstantValue::Bytes(value) => {
            output.push(TAG_BYTES);
            let length = u32::try_from(value.len()).map_err(|_| {
                DataProtectionError::InvalidConstant("byte constant exceeds u32 length".into())
            })?;
            output.extend_from_slice(&length.to_le_bytes());
            output.extend_from_slice(value);
        }
    }
    Ok(output)
}

pub fn decode(bytes: &[u8]) -> Result<ConstantValue> {
    let (&tag, body) = bytes
        .split_first()
        .ok_or_else(|| DataProtectionError::InvalidConstant("constant payload is empty".into()))?;

    match tag {
        TAG_BOOL => {
            if body.len() != 1 || body[0] > 1 {
                return Err(DataProtectionError::InvalidConstant(
                    "invalid boolean payload".into(),
                ));
            }
            Ok(ConstantValue::Bool(body[0] == 1))
        }
        TAG_I32 => Ok(ConstantValue::I32(i32::from_le_bytes(read_array(body)?))),
        TAG_I64 => Ok(ConstantValue::I64(i64::from_le_bytes(read_array(body)?))),
        TAG_F32 => Ok(ConstantValue::F32(f32::from_bits(u32::from_le_bytes(
            read_array(body)?,
        )))),
        TAG_F64 => Ok(ConstantValue::F64(f64::from_bits(u64::from_le_bytes(
            read_array(body)?,
        )))),
        TAG_BYTES => {
            if body.len() < 4 {
                return Err(DataProtectionError::InvalidConstant(
                    "truncated byte constant length".into(),
                ));
            }
            let mut length_bytes = [0_u8; 4];
            length_bytes.copy_from_slice(&body[..4]);
            let length = usize::try_from(u32::from_le_bytes(length_bytes)).map_err(|_| {
                DataProtectionError::InvalidConstant(
                    "byte constant length does not fit usize".into(),
                )
            })?;
            let payload = &body[4..];
            if payload.len() != length {
                return Err(DataProtectionError::InvalidConstant(
                    "byte constant length mismatch".into(),
                ));
            }
            Ok(ConstantValue::Bytes(payload.to_vec()))
        }
        other => Err(DataProtectionError::InvalidConstant(format!(
            "unknown constant tag {other}"
        ))),
    }
}

fn read_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    if bytes.len() != N {
        return Err(DataProtectionError::InvalidConstant(format!(
            "constant payload has {} bytes, expected {N}",
            bytes.len()
        )));
    }
    let mut output = [0_u8; N];
    output.copy_from_slice(bytes);
    Ok(output)
}
