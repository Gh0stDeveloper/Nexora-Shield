use crate::error::{DexError, Result};
use crate::model::{DexFile, ACC_STATIC};

const ACC_ABSTRACT: u32 = 0x0400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub classes: usize,
    pub methods: usize,
    pub code_items: usize,
    pub instructions: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DexValidator;

impl DexValidator {
    pub fn validate(dex: &DexFile) -> Result<ValidationReport> {
        for (index, type_id) in dex.types.iter().enumerate() {
            let descriptor = dex.string(type_id.descriptor_idx).ok_or(DexError::InvalidIndex {
                kind: "string",
                index: type_id.descriptor_idx,
            })?;
            validate_type_descriptor(descriptor).map_err(|message| {
                DexError::InvalidHeader(format!("type[{index}] descriptor: {message}"))
            })?;
        }

        for (index, proto) in dex.protos.iter().enumerate() {
            let shorty = dex.string(proto.shorty_idx).ok_or(DexError::InvalidIndex {
                kind: "string",
                index: proto.shorty_idx,
            })?;
            let expected = proto_shorty(dex, index as u32)?;
            if shorty != expected {
                return Err(DexError::InvalidHeader(format!(
                    "proto[{index}] shorty '{shorty}' does not match '{expected}'"
                )));
            }
        }

        for class in &dex.classes {
            if let Some(data) = dex.class_data.get(&class.class_idx) {
                for encoded in data.static_fields.iter().chain(data.instance_fields.iter()) {
                    let field = dex.fields.get(encoded.field_idx as usize).ok_or(
                        DexError::InvalidIndex {
                            kind: "field",
                            index: encoded.field_idx,
                        },
                    )?;
                    if u32::from(field.class_idx) != class.class_idx {
                        return Err(DexError::InvalidHeader(format!(
                            "field {} is encoded under the wrong class",
                            encoded.field_idx
                        )));
                    }
                }

                for encoded in data.methods() {
                    let method = dex.methods.get(encoded.method_idx as usize).ok_or(
                        DexError::InvalidIndex {
                            kind: "method",
                            index: encoded.method_idx,
                        },
                    )?;
                    if u32::from(method.class_idx) != class.class_idx {
                        return Err(DexError::InvalidHeader(format!(
                            "method {} is encoded under the wrong class",
                            encoded.method_idx
                        )));
                    }

                    let no_code_expected =
                        encoded.access_flags & (crate::model::ACC_NATIVE | ACC_ABSTRACT) != 0;
                    if no_code_expected && encoded.code_off != 0 {
                        return Err(DexError::InvalidHeader(format!(
                            "native/abstract method {} has code_off {}",
                            encoded.method_idx, encoded.code_off
                        )));
                    }

                    if let Some(code) = dex.code_items.get(&encoded.code_off) {
                        let proto = &dex.protos[method.proto_idx as usize];
                        let parameter_words = parameter_word_count(dex, proto)?;
                        let receiver_words = usize::from(encoded.access_flags & ACC_STATIC == 0);
                        let expected_ins = parameter_words + receiver_words;
                        if usize::from(code.ins_size) != expected_ins {
                            return Err(DexError::InvalidInstruction {
                                offset: 0,
                                reason: format!(
                                    "method {} ins_size {} does not match parameter word count {}",
                                    encoded.method_idx, code.ins_size, expected_ins
                                ),
                            });
                        }
                    }
                }
            }
        }

        let instructions = dex
            .code_items
            .values()
            .map(|code| code.instructions.len())
            .sum();

        Ok(ValidationReport {
            classes: dex.classes.len(),
            methods: dex.methods.len(),
            code_items: dex.code_items.len(),
            instructions,
            warnings: Vec::new(),
        })
    }
}

fn parameter_word_count(dex: &DexFile, proto: &crate::model::ProtoId) -> Result<usize> {
    let mut words = 0_usize;
    for type_index in &proto.parameters {
        let descriptor = dex
            .type_descriptor(u32::from(*type_index))
            .ok_or(DexError::InvalidIndex {
                kind: "type",
                index: u32::from(*type_index),
            })?;
        words += usize::from(matches!(descriptor, "J" | "D")) + 1;
    }
    Ok(words)
}

fn proto_shorty(dex: &DexFile, proto_index: u32) -> Result<String> {
    let proto = dex.protos.get(proto_index as usize).ok_or(DexError::InvalidIndex {
        kind: "proto",
        index: proto_index,
    })?;
    let mut shorty = String::new();
    let return_descriptor = dex
        .type_descriptor(proto.return_type_idx)
        .ok_or(DexError::InvalidIndex {
            kind: "type",
            index: proto.return_type_idx,
        })?;
    shorty.push(shorty_char(return_descriptor)?);
    for parameter in &proto.parameters {
        let descriptor = dex
            .type_descriptor(u32::from(*parameter))
            .ok_or(DexError::InvalidIndex {
                kind: "type",
                index: u32::from(*parameter),
            })?;
        shorty.push(shorty_char(descriptor)?);
    }
    Ok(shorty)
}

fn shorty_char(descriptor: &str) -> Result<char> {
    let first = descriptor
        .chars()
        .next()
        .ok_or_else(|| DexError::InvalidHeader("empty type descriptor".into()))?;
    Ok(match first {
        'L' | '[' => 'L',
        primitive => primitive,
    })
}

fn validate_type_descriptor(descriptor: &str) -> std::result::Result<(), String> {
    if descriptor.is_empty() {
        return Err("empty descriptor".into());
    }
    let bytes = descriptor.as_bytes();
    match bytes[0] {
        b'V' | b'Z' | b'B' | b'S' | b'C' | b'I' | b'J' | b'F' | b'D' if bytes.len() == 1 => Ok(()),
        b'[' => {
            let mut dimensions = 0_usize;
            while dimensions < bytes.len() && bytes[dimensions] == b'[' {
                dimensions += 1;
            }
            if dimensions > 255 || dimensions == bytes.len() {
                return Err("invalid array descriptor".into());
            }
            if bytes[dimensions] == b'V' {
                return Err("array component cannot be void".into());
            }
            validate_type_descriptor(&descriptor[dimensions..])
        }
        b'L' => {
            if !descriptor.ends_with(';') || descriptor.len() < 3 {
                return Err("object descriptor must end in ';'".into());
            }
            let body = &descriptor[1..descriptor.len() - 1];
            if body.starts_with('/') || body.ends_with('/') || body.contains("//") {
                return Err("object descriptor has an invalid package path".into());
            }
            if body.bytes().any(|byte| matches!(byte, b'.' | b';' | b'[' | 0)) {
                return Err("object descriptor contains a forbidden character".into());
            }
            Ok(())
        }
        _ => Err("unknown descriptor form".into()),
    }
}
