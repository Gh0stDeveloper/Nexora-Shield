use crate::{runtime_smali::refuse, Result};
use nexora_shield_crypto::ConstantValue;
use nexora_shield_dex::DexFile;
use nexora_shield_native::{RuntimeEntryKind, RuntimeImage};

pub(super) fn protect_literal(
    dex: &DexFile,
    index: u32,
    slot: u32,
    image: &mut RuntimeImage,
) -> Result<Option<RuntimeEntryKind>> {
    let method = &dex.methods[index as usize];
    let proto = &dex.protos[usize::from(method.proto_idx)];
    let result = dex
        .type_descriptor(proto.return_type_idx)
        .ok_or_else(|| refuse("invalid constant return type"))?;
    if !proto.parameters.is_empty() || !matches!(result, "Z" | "I" | "J" | "F" | "D") {
        return Ok(None);
    }
    let code = dex
        .code_for_method(index)
        .ok_or_else(|| refuse("missing constant code"))?;
    if !code.tries.is_empty() || code.instructions.len() != 2 {
        return Ok(None);
    }
    let first = &code.instructions[0];
    let ret = &code.instructions[1];
    let wide = matches!(result, "J" | "D");
    if first.offset != 0
        || !matches!(first.opcode, 0x12..=0x19)
        || ret.opcode != if wide { 0x10 } else { 0x0f }
    {
        return Ok(None);
    }
    if wide != matches!(first.opcode, 0x16..=0x19) {
        return Err(refuse("constant opcode width differs from return contract"));
    }
    let register = if first.opcode == 0x12 {
        (code.insns[0] >> 8) & 0x0f
    } else {
        code.insns[0] >> 8
    };
    if register != code.insns[ret.offset as usize] >> 8 {
        return Ok(None);
    }
    let value = match result {
        "Z" => match bits32(&code.insns, first.opcode)? {
            0 => ConstantValue::Bool(false),
            1 => ConstantValue::Bool(true),
            _ => return Err(refuse("invalid boolean literal getter")),
        },
        "I" => ConstantValue::I32(i32::from_le_bytes(
            bits32(&code.insns, first.opcode)?.to_le_bytes(),
        )),
        "J" => ConstantValue::I64(i64::from_le_bytes(
            bits64(&code.insns, first.opcode)?.to_le_bytes(),
        )),
        "F" => {
            let value = f32::from_bits(bits32(&code.insns, first.opcode)?);
            if value.is_nan() {
                return Err(refuse(
                    "NaN literal getter requires a verified platform bit contract",
                ));
            }
            ConstantValue::F32(value)
        }
        "D" => {
            let value = f64::from_bits(bits64(&code.insns, first.opcode)?);
            if value.is_nan() {
                return Err(refuse(
                    "NaN literal getter requires a verified platform bit contract",
                ));
            }
            ConstantValue::F64(value)
        }
        _ => return Err(refuse("unsupported constant return type")),
    };
    image
        .protect_constant(slot, &value)
        .map_err(|_| refuse("runtime constant protection failed"))?;
    Ok(Some(RuntimeEntryKind::Constant))
}

fn unit(words: &[u16], at: usize) -> Result<u16> {
    words
        .get(at)
        .copied()
        .ok_or_else(|| refuse("truncated constant operand"))
}
fn bits32(words: &[u16], opcode: u8) -> Result<u32> {
    match opcode {
        0x12 => {
            let nibble = (unit(words, 0)? >> 12) & 0xf;
            let value = if nibble & 8 == 0 {
                i32::from(nibble)
            } else {
                i32::from(nibble) - 16
            };
            Ok(u32::from_le_bytes(value.to_le_bytes()))
        }
        0x13 => Ok(u32::from_le_bytes(
            i32::from(i16::from_le_bytes(unit(words, 1)?.to_le_bytes())).to_le_bytes(),
        )),
        0x14 => Ok(u32::from(unit(words, 1)?) | (u32::from(unit(words, 2)?) << 16)),
        0x15 => Ok(u32::from(unit(words, 1)?) << 16),
        _ => Err(refuse("unsupported narrow constant opcode")),
    }
}
fn bits64(words: &[u16], opcode: u8) -> Result<u64> {
    match opcode {
        0x16 => Ok(u64::from_le_bytes(
            i64::from(i16::from_le_bytes(unit(words, 1)?.to_le_bytes())).to_le_bytes(),
        )),
        0x17 => {
            let bits = u32::from(unit(words, 1)?) | (u32::from(unit(words, 2)?) << 16);
            Ok(u64::from_le_bytes(
                i64::from(i32::from_le_bytes(bits.to_le_bytes())).to_le_bytes(),
            ))
        }
        0x18 => {
            let mut bits = 0;
            for n in 0..4 {
                bits |= u64::from(unit(words, n + 1)?) << (n * 16);
            }
            Ok(bits)
        }
        0x19 => Ok(u64::from(unit(words, 1)?) << 48),
        _ => Err(refuse("unsupported wide constant opcode")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dex_constant_formats_preserve_sign_extension_and_wide_bits() -> Result<()> {
        assert_eq!(bits32(&[0xf012], 0x12)?, u32::MAX);
        assert_eq!(bits32(&[0x13, 0x8000], 0x13)?, 0xffff_8000);
        assert_eq!(bits32(&[0x14, 0x9bdf, 0x1357], 0x14)?, 0x1357_9bdf);
        assert_eq!(bits32(&[0x15, 0x8000], 0x15)?, 0x8000_0000);
        assert_eq!(bits64(&[0x16, 0xffff], 0x16)?, u64::MAX);
        assert_eq!(bits64(&[0x17, 0, 0x8000], 0x17)?, 0xffff_ffff_8000_0000);
        assert_eq!(
            bits64(&[0x18, 0x3210, 0x7654, 0xba98, 0xfedc], 0x18)?,
            0xfedc_ba98_7654_3210
        );
        assert_eq!(bits64(&[0x19, 0x8000], 0x19)?, 1u64 << 63);
        assert!(bits64(&[0x18, 1], 0x18).is_err());
        Ok(())
    }
}
