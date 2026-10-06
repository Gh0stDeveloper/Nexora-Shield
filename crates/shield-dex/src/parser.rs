use crate::checksum::verify_integrity;
use crate::error::{DexError, Result};
use crate::model::{
    CatchHandler, ClassData, ClassDef, CodeItem, DexFile, DexHeader, DexString, EncodedField,
    EncodedMethod, FieldId, Instruction, MethodId, ProtoId, PseudoInstruction, ReferenceKind,
    TryItem, TypeId, DEX_ENDIAN_CONSTANT, DEX_HEADER_SIZE, NO_INDEX,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, Clone, Copy)]
pub struct DexParser;

impl DexParser {
    pub fn parse(bytes: &[u8]) -> Result<DexFile> {
        let header = parse_header(bytes)?;
        verify_integrity(bytes)?;
        validate_fixed_sections(bytes, &header)?;

        let strings = parse_strings(bytes, &header)?;
        let types = parse_types(bytes, &header, strings.len())?;
        let protos = parse_protos(bytes, &header, strings.len(), types.len())?;
        let fields = parse_fields(bytes, &header, strings.len(), types.len())?;
        let methods = parse_methods(bytes, &header, strings.len(), types.len(), protos.len())?;
        let classes = parse_classes(bytes, &header, strings.len(), types.len())?;

        let mut class_data = BTreeMap::new();
        let mut code_items = BTreeMap::new();
        let mut seen_class_types = BTreeSet::new();

        for class_def in &classes {
            if !seen_class_types.insert(class_def.class_idx) {
                return Err(DexError::InvalidHeader(format!(
                    "duplicate class definition for type index {}",
                    class_def.class_idx
                )));
            }
            if class_def.class_data_off == 0 {
                continue;
            }

            let data =
                parse_class_data(bytes, class_def.class_data_off, fields.len(), methods.len())?;

            for method in data.methods() {
                if method.code_off == 0 {
                    continue;
                }
                if method.code_off % 4 != 0 {
                    return Err(DexError::InvalidOffset {
                        context: "code_item alignment".into(),
                        offset: method.code_off,
                    });
                }
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    code_items.entry(method.code_off)
                {
                    let code = parse_code_item(
                        bytes,
                        method.code_off,
                        strings.len(),
                        types.len(),
                        fields.len(),
                        methods.len(),
                        protos.len(),
                    )?;
                    entry.insert(code);
                }
            }

            class_data.insert(class_def.class_idx, data);
        }

        Ok(DexFile {
            bytes: bytes.to_vec(),
            header,
            strings,
            types,
            protos,
            fields,
            methods,
            classes,
            class_data,
            code_items,
        })
    }
}

fn parse_header(bytes: &[u8]) -> Result<DexHeader> {
    ensure(bytes, 0, DEX_HEADER_SIZE as usize, "DEX header")?;
    if &bytes[..4] != b"dex\n" || bytes[7] != 0 {
        return Err(DexError::InvalidHeader("magic is not dex\\nNNN\\0".into()));
    }
    if !bytes[4..7].iter().all(u8::is_ascii_digit) {
        return Err(DexError::InvalidHeader(
            "version is not three ASCII digits".into(),
        ));
    }

    let version = std::str::from_utf8(&bytes[4..7])
        .map_err(|_| DexError::InvalidHeader("version is not valid ASCII".into()))?
        .to_owned();

    let mut signature = [0_u8; 20];
    signature.copy_from_slice(&bytes[12..32]);

    let header = DexHeader {
        version,
        checksum: read_u32(bytes, 8, "checksum")?,
        signature,
        file_size: read_u32(bytes, 32, "file_size")?,
        header_size: read_u32(bytes, 36, "header_size")?,
        endian_tag: read_u32(bytes, 40, "endian_tag")?,
        link_size: read_u32(bytes, 44, "link_size")?,
        link_off: read_u32(bytes, 48, "link_off")?,
        map_off: read_u32(bytes, 52, "map_off")?,
        string_ids_size: read_u32(bytes, 56, "string_ids_size")?,
        string_ids_off: read_u32(bytes, 60, "string_ids_off")?,
        type_ids_size: read_u32(bytes, 64, "type_ids_size")?,
        type_ids_off: read_u32(bytes, 68, "type_ids_off")?,
        proto_ids_size: read_u32(bytes, 72, "proto_ids_size")?,
        proto_ids_off: read_u32(bytes, 76, "proto_ids_off")?,
        field_ids_size: read_u32(bytes, 80, "field_ids_size")?,
        field_ids_off: read_u32(bytes, 84, "field_ids_off")?,
        method_ids_size: read_u32(bytes, 88, "method_ids_size")?,
        method_ids_off: read_u32(bytes, 92, "method_ids_off")?,
        class_defs_size: read_u32(bytes, 96, "class_defs_size")?,
        class_defs_off: read_u32(bytes, 100, "class_defs_off")?,
        data_size: read_u32(bytes, 104, "data_size")?,
        data_off: read_u32(bytes, 108, "data_off")?,
    };

    if header.header_size != DEX_HEADER_SIZE {
        return Err(DexError::InvalidHeader(format!(
            "header_size is {}, expected {}",
            header.header_size, DEX_HEADER_SIZE
        )));
    }
    if header.endian_tag != DEX_ENDIAN_CONSTANT {
        return Err(DexError::InvalidHeader(format!(
            "unsupported endian tag 0x{:08x}",
            header.endian_tag
        )));
    }
    if usize::try_from(header.file_size).ok() != Some(bytes.len()) {
        return Err(DexError::InvalidHeader(format!(
            "file_size {} does not match actual size {}",
            header.file_size,
            bytes.len()
        )));
    }

    let data_end = u64::from(header.data_off) + u64::from(header.data_size);
    if data_end > bytes.len() as u64 {
        return Err(DexError::InvalidHeader(
            "data section extends past end of file".into(),
        ));
    }

    Ok(header)
}

fn validate_fixed_sections(bytes: &[u8], header: &DexHeader) -> Result<()> {
    validate_section(
        bytes,
        header.string_ids_off,
        header.string_ids_size,
        4,
        "string_ids",
    )?;
    validate_section(
        bytes,
        header.type_ids_off,
        header.type_ids_size,
        4,
        "type_ids",
    )?;
    validate_section(
        bytes,
        header.proto_ids_off,
        header.proto_ids_size,
        12,
        "proto_ids",
    )?;
    validate_section(
        bytes,
        header.field_ids_off,
        header.field_ids_size,
        8,
        "field_ids",
    )?;
    validate_section(
        bytes,
        header.method_ids_off,
        header.method_ids_size,
        8,
        "method_ids",
    )?;
    validate_section(
        bytes,
        header.class_defs_off,
        header.class_defs_size,
        32,
        "class_defs",
    )?;

    for (offset, name) in [
        (header.string_ids_off, "string_ids"),
        (header.type_ids_off, "type_ids"),
        (header.proto_ids_off, "proto_ids"),
        (header.field_ids_off, "field_ids"),
        (header.method_ids_off, "method_ids"),
        (header.class_defs_off, "class_defs"),
    ] {
        if offset != 0 && offset % 4 != 0 {
            return Err(DexError::InvalidOffset {
                context: format!("{name} alignment"),
                offset,
            });
        }
    }
    Ok(())
}

fn validate_section(
    bytes: &[u8],
    offset: u32,
    count: u32,
    item_size: u32,
    context: &str,
) -> Result<()> {
    if count == 0 {
        if offset != 0 {
            return Err(DexError::InvalidOffset {
                context: format!("{context} must use offset 0 when empty"),
                offset,
            });
        }
        return Ok(());
    }
    if offset == 0 {
        return Err(DexError::InvalidOffset {
            context: format!("{context} has non-zero size with zero offset"),
            offset,
        });
    }
    let end = u64::from(offset) + u64::from(count) * u64::from(item_size);
    if end > bytes.len() as u64 {
        return Err(DexError::InvalidOffset {
            context: context.to_owned(),
            offset,
        });
    }
    Ok(())
}

fn parse_strings(bytes: &[u8], header: &DexHeader) -> Result<Vec<DexString>> {
    let mut strings = Vec::with_capacity(header.string_ids_size as usize);
    for index in 0..header.string_ids_size {
        let item_off = header.string_ids_off + index * 4;
        let data_off = read_u32(bytes, item_off as usize, "string_data_off")?;
        if data_off < header.data_off || data_off >= header.file_size {
            return Err(DexError::InvalidOffset {
                context: format!("string_data[{index}]"),
                offset: data_off,
            });
        }
        strings.push(parse_string_data(bytes, data_off)?);
    }
    Ok(strings)
}

fn parse_string_data(bytes: &[u8], offset: u32) -> Result<DexString> {
    let start = offset as usize;
    let (utf16_len, data_start) = read_uleb128(bytes, start)?;
    let mut cursor = data_start;
    let mut units = Vec::<u16>::new();

    loop {
        let first = *bytes.get(cursor).ok_or_else(|| DexError::Truncated {
            context: "string_data_item".into(),
            offset: cursor,
        })?;
        if first == 0 {
            break;
        }

        if first & 0x80 == 0 {
            units.push(u16::from(first));
            cursor += 1;
            continue;
        }

        if first & 0xe0 == 0xc0 {
            let second = *bytes.get(cursor + 1).ok_or_else(|| DexError::Truncated {
                context: "two-byte modified UTF-8 sequence".into(),
                offset: cursor,
            })?;
            if second & 0xc0 != 0x80 {
                return Err(DexError::InvalidMutf8 {
                    offset: cursor,
                    reason: "invalid continuation byte".into(),
                });
            }
            let value = (u16::from(first & 0x1f) << 6) | u16::from(second & 0x3f);
            if value == 0 {
                if first != 0xc0 || second != 0x80 {
                    return Err(DexError::InvalidMutf8 {
                        offset: cursor,
                        reason: "non-canonical encoded NUL".into(),
                    });
                }
            } else if value < 0x80 {
                return Err(DexError::InvalidMutf8 {
                    offset: cursor,
                    reason: "overlong two-byte sequence".into(),
                });
            }
            units.push(value);
            cursor += 2;
            continue;
        }

        if first & 0xf0 == 0xe0 {
            let second = *bytes.get(cursor + 1).ok_or_else(|| DexError::Truncated {
                context: "three-byte modified UTF-8 sequence".into(),
                offset: cursor,
            })?;
            let third = *bytes.get(cursor + 2).ok_or_else(|| DexError::Truncated {
                context: "three-byte modified UTF-8 sequence".into(),
                offset: cursor,
            })?;
            if second & 0xc0 != 0x80 || third & 0xc0 != 0x80 {
                return Err(DexError::InvalidMutf8 {
                    offset: cursor,
                    reason: "invalid continuation byte".into(),
                });
            }
            let value = (u16::from(first & 0x0f) << 12)
                | (u16::from(second & 0x3f) << 6)
                | u16::from(third & 0x3f);
            if value < 0x800 {
                return Err(DexError::InvalidMutf8 {
                    offset: cursor,
                    reason: "overlong three-byte sequence".into(),
                });
            }
            units.push(value);
            cursor += 3;
            continue;
        }

        return Err(DexError::InvalidMutf8 {
            offset: cursor,
            reason: "four-byte UTF-8 sequences are not valid DEX MUTF-8".into(),
        });
    }

    if units.len() != utf16_len as usize {
        return Err(DexError::InvalidMutf8 {
            offset: start,
            reason: format!(
                "declared UTF-16 length {utf16_len} differs from decoded length {}",
                units.len()
            ),
        });
    }

    let value = String::from_utf16(&units).map_err(|error| DexError::InvalidMutf8 {
        offset: start,
        reason: error.to_string(),
    })?;
    let byte_len = cursor - data_start;

    Ok(DexString {
        value,
        data_offset: offset,
        data_start: data_start as u32,
        byte_len: byte_len as u32,
        utf16_len,
    })
}

fn parse_types(bytes: &[u8], header: &DexHeader, string_count: usize) -> Result<Vec<TypeId>> {
    let mut result = Vec::with_capacity(header.type_ids_size as usize);
    for index in 0..header.type_ids_size {
        let offset = (header.type_ids_off + index * 4) as usize;
        let descriptor_idx = read_u32(bytes, offset, "type descriptor_idx")?;
        validate_index("string", descriptor_idx, string_count)?;
        result.push(TypeId { descriptor_idx });
    }
    Ok(result)
}

fn parse_protos(
    bytes: &[u8],
    header: &DexHeader,
    string_count: usize,
    type_count: usize,
) -> Result<Vec<ProtoId>> {
    let mut result = Vec::with_capacity(header.proto_ids_size as usize);
    for index in 0..header.proto_ids_size {
        let offset = (header.proto_ids_off + index * 12) as usize;
        let shorty_idx = read_u32(bytes, offset, "proto shorty_idx")?;
        let return_type_idx = read_u32(bytes, offset + 4, "proto return_type_idx")?;
        let parameters_off = read_u32(bytes, offset + 8, "proto parameters_off")?;
        validate_index("string", shorty_idx, string_count)?;
        validate_index("type", return_type_idx, type_count)?;
        let parameters = if parameters_off == 0 {
            Vec::new()
        } else {
            parse_type_list(bytes, parameters_off, type_count)?
        };
        result.push(ProtoId {
            shorty_idx,
            return_type_idx,
            parameters_off,
            parameters,
        });
    }
    Ok(result)
}

fn parse_type_list(bytes: &[u8], offset: u32, type_count: usize) -> Result<Vec<u16>> {
    if offset % 4 != 0 {
        return Err(DexError::InvalidOffset {
            context: "type_list alignment".into(),
            offset,
        });
    }
    let count = read_u32(bytes, offset as usize, "type_list size")?;
    let end = u64::from(offset) + 4 + u64::from(count) * 2;
    if end > bytes.len() as u64 {
        return Err(DexError::InvalidOffset {
            context: "type_list".into(),
            offset,
        });
    }
    let mut result = Vec::with_capacity(count as usize);
    for index in 0..count {
        let item = read_u16(
            bytes,
            offset as usize + 4 + index as usize * 2,
            "type_list item",
        )?;
        validate_index("type", u32::from(item), type_count)?;
        result.push(item);
    }
    Ok(result)
}

fn parse_fields(
    bytes: &[u8],
    header: &DexHeader,
    string_count: usize,
    type_count: usize,
) -> Result<Vec<FieldId>> {
    let mut result = Vec::with_capacity(header.field_ids_size as usize);
    for index in 0..header.field_ids_size {
        let offset = (header.field_ids_off + index * 8) as usize;
        let class_idx = read_u16(bytes, offset, "field class_idx")?;
        let type_idx = read_u16(bytes, offset + 2, "field type_idx")?;
        let name_idx = read_u32(bytes, offset + 4, "field name_idx")?;
        validate_index("type", u32::from(class_idx), type_count)?;
        validate_index("type", u32::from(type_idx), type_count)?;
        validate_index("string", name_idx, string_count)?;
        result.push(FieldId {
            class_idx,
            type_idx,
            name_idx,
        });
    }
    Ok(result)
}

fn parse_methods(
    bytes: &[u8],
    header: &DexHeader,
    string_count: usize,
    type_count: usize,
    proto_count: usize,
) -> Result<Vec<MethodId>> {
    let mut result = Vec::with_capacity(header.method_ids_size as usize);
    for index in 0..header.method_ids_size {
        let offset = (header.method_ids_off + index * 8) as usize;
        let class_idx = read_u16(bytes, offset, "method class_idx")?;
        let proto_idx = read_u16(bytes, offset + 2, "method proto_idx")?;
        let name_idx = read_u32(bytes, offset + 4, "method name_idx")?;
        validate_index("type", u32::from(class_idx), type_count)?;
        validate_index("proto", u32::from(proto_idx), proto_count)?;
        validate_index("string", name_idx, string_count)?;
        result.push(MethodId {
            class_idx,
            proto_idx,
            name_idx,
        });
    }
    Ok(result)
}

fn parse_classes(
    bytes: &[u8],
    header: &DexHeader,
    string_count: usize,
    type_count: usize,
) -> Result<Vec<ClassDef>> {
    let mut result = Vec::with_capacity(header.class_defs_size as usize);
    for index in 0..header.class_defs_size {
        let offset = (header.class_defs_off + index * 32) as usize;
        let class_def = ClassDef {
            class_idx: read_u32(bytes, offset, "class_idx")?,
            access_flags: read_u32(bytes, offset + 4, "class access_flags")?,
            superclass_idx: read_u32(bytes, offset + 8, "superclass_idx")?,
            interfaces_off: read_u32(bytes, offset + 12, "interfaces_off")?,
            source_file_idx: read_u32(bytes, offset + 16, "source_file_idx")?,
            annotations_off: read_u32(bytes, offset + 20, "annotations_off")?,
            class_data_off: read_u32(bytes, offset + 24, "class_data_off")?,
            static_values_off: read_u32(bytes, offset + 28, "static_values_off")?,
        };
        validate_index("type", class_def.class_idx, type_count)?;
        if class_def.superclass_idx != NO_INDEX {
            validate_index("type", class_def.superclass_idx, type_count)?;
        }
        if class_def.source_file_idx != NO_INDEX {
            validate_index("string", class_def.source_file_idx, string_count)?;
        }
        if class_def.interfaces_off != 0 {
            let _ = parse_type_list(bytes, class_def.interfaces_off, type_count)?;
        }
        for (name, item_offset) in [
            ("annotations_off", class_def.annotations_off),
            ("class_data_off", class_def.class_data_off),
            ("static_values_off", class_def.static_values_off),
        ] {
            if item_offset != 0 && item_offset >= header.file_size {
                return Err(DexError::InvalidOffset {
                    context: name.into(),
                    offset: item_offset,
                });
            }
        }
        result.push(class_def);
    }
    Ok(result)
}

fn parse_class_data(
    bytes: &[u8],
    offset: u32,
    field_count: usize,
    method_count: usize,
) -> Result<ClassData> {
    let mut cursor = offset as usize;
    let (static_fields_size, next) = read_uleb128(bytes, cursor)?;
    cursor = next;
    let (instance_fields_size, next) = read_uleb128(bytes, cursor)?;
    cursor = next;
    let (direct_methods_size, next) = read_uleb128(bytes, cursor)?;
    cursor = next;
    let (virtual_methods_size, next) = read_uleb128(bytes, cursor)?;
    cursor = next;

    let (static_fields, next) =
        parse_encoded_fields(bytes, cursor, static_fields_size, field_count)?;
    cursor = next;
    let (instance_fields, next) =
        parse_encoded_fields(bytes, cursor, instance_fields_size, field_count)?;
    cursor = next;
    let (direct_methods, next) =
        parse_encoded_methods(bytes, cursor, direct_methods_size, method_count)?;
    cursor = next;
    let (virtual_methods, _) =
        parse_encoded_methods(bytes, cursor, virtual_methods_size, method_count)?;

    Ok(ClassData {
        static_fields,
        instance_fields,
        direct_methods,
        virtual_methods,
    })
}

fn parse_encoded_fields(
    bytes: &[u8],
    mut cursor: usize,
    count: u32,
    field_count: usize,
) -> Result<(Vec<EncodedField>, usize)> {
    let mut result = Vec::with_capacity(count as usize);
    let mut field_idx = 0_u32;
    for ordinal in 0..count {
        let (diff, next) = read_uleb128(bytes, cursor)?;
        cursor = next;
        let (access_flags, next) = read_uleb128(bytes, cursor)?;
        cursor = next;
        field_idx = if ordinal == 0 {
            diff
        } else {
            field_idx.checked_add(diff).ok_or(DexError::InvalidIndex {
                kind: "encoded field",
                index: u32::MAX,
            })?
        };
        validate_index("field", field_idx, field_count)?;
        result.push(EncodedField {
            field_idx,
            access_flags,
        });
    }
    Ok((result, cursor))
}

fn parse_encoded_methods(
    bytes: &[u8],
    mut cursor: usize,
    count: u32,
    method_count: usize,
) -> Result<(Vec<EncodedMethod>, usize)> {
    let mut result = Vec::with_capacity(count as usize);
    let mut method_idx = 0_u32;
    for ordinal in 0..count {
        let (diff, next) = read_uleb128(bytes, cursor)?;
        cursor = next;
        let (access_flags, next) = read_uleb128(bytes, cursor)?;
        cursor = next;
        let (code_off, next) = read_uleb128(bytes, cursor)?;
        cursor = next;
        method_idx = if ordinal == 0 {
            diff
        } else {
            method_idx.checked_add(diff).ok_or(DexError::InvalidIndex {
                kind: "encoded method",
                index: u32::MAX,
            })?
        };
        validate_index("method", method_idx, method_count)?;
        result.push(EncodedMethod {
            method_idx,
            access_flags,
            code_off,
        });
    }
    Ok((result, cursor))
}

fn parse_code_item(
    bytes: &[u8],
    offset: u32,
    string_count: usize,
    type_count: usize,
    field_count: usize,
    method_count: usize,
    proto_count: usize,
) -> Result<CodeItem> {
    let start = offset as usize;
    ensure(bytes, start, 16, "code_item header")?;
    let registers_size = read_u16(bytes, start, "registers_size")?;
    let ins_size = read_u16(bytes, start + 2, "ins_size")?;
    let outs_size = read_u16(bytes, start + 4, "outs_size")?;
    let tries_size = read_u16(bytes, start + 6, "tries_size")?;
    let debug_info_off = read_u32(bytes, start + 8, "debug_info_off")?;
    let insns_size = read_u32(bytes, start + 12, "insns_size")?;

    if ins_size > registers_size {
        return Err(DexError::InvalidInstruction {
            offset: 0,
            reason: format!("ins_size {ins_size} exceeds registers_size {registers_size}"),
        });
    }

    let insn_bytes = u64::from(insns_size) * 2;
    let insns_start = start + 16;
    let insns_end = u64::try_from(insns_start)
        .ok()
        .and_then(|value| value.checked_add(insn_bytes))
        .ok_or_else(|| DexError::InvalidOffset {
            context: "code_item insns overflow".into(),
            offset,
        })?;
    if insns_end > bytes.len() as u64 {
        return Err(DexError::InvalidOffset {
            context: "code_item instructions".into(),
            offset,
        });
    }

    let mut insns = Vec::with_capacity(insns_size as usize);
    for index in 0..insns_size {
        insns.push(read_u16(
            bytes,
            insns_start + index as usize * 2,
            "instruction code unit",
        )?);
    }

    let instructions = decode_instructions(
        &insns,
        string_count,
        type_count,
        field_count,
        method_count,
        proto_count,
    )?;

    let mut cursor = insns_end as usize;
    if tries_size != 0 && insns_size % 2 != 0 {
        ensure(bytes, cursor, 2, "code_item padding")?;
        cursor += 2;
    }

    let mut tries = Vec::with_capacity(tries_size as usize);
    for _ in 0..tries_size {
        ensure(bytes, cursor, 8, "try_item")?;
        let start_addr = read_u32(bytes, cursor, "try start_addr")?;
        let insn_count = read_u16(bytes, cursor + 4, "try insn_count")?;
        let handler_off = read_u16(bytes, cursor + 6, "try handler_off")?;
        let try_end = u64::from(start_addr) + u64::from(insn_count);
        if try_end > u64::from(insns_size) {
            return Err(DexError::InvalidControlFlow {
                offset: start_addr,
                target: try_end as i64,
            });
        }
        tries.push(TryItem {
            start_addr,
            insn_count,
            handler_off,
        });
        cursor += 8;
    }

    let handlers = if tries_size == 0 {
        Vec::new()
    } else {
        parse_catch_handlers(bytes, cursor, type_count, insns_size)?
    };

    if tries_size != 0 {
        for try_item in &tries {
            if !handlers
                .iter()
                .any(|handler| handler.relative_offset == u32::from(try_item.handler_off))
            {
                return Err(DexError::InvalidOffset {
                    context: "try_item handler_off".into(),
                    offset: u32::from(try_item.handler_off),
                });
            }
        }
    }

    Ok(CodeItem {
        offset,
        registers_size,
        ins_size,
        outs_size,
        tries_size,
        debug_info_off,
        insns_size,
        insns,
        instructions,
        tries,
        handlers,
    })
}

fn parse_catch_handlers(
    bytes: &[u8],
    start: usize,
    type_count: usize,
    insns_size: u32,
) -> Result<Vec<CatchHandler>> {
    let (handler_count, mut cursor) = read_uleb128(bytes, start)?;
    let mut result = Vec::with_capacity(handler_count as usize);

    for _ in 0..handler_count {
        let relative_offset =
            u32::try_from(cursor - start).map_err(|_| DexError::InvalidOffset {
                context: "catch handler relative offset".into(),
                offset: u32::MAX,
            })?;
        let (signed_size, next) = read_sleb128(bytes, cursor)?;
        cursor = next;
        let typed_count = signed_size.unsigned_abs();
        let mut typed_handlers = Vec::with_capacity(typed_count as usize);

        for _ in 0..typed_count {
            let (type_idx, next) = read_uleb128(bytes, cursor)?;
            cursor = next;
            let (address, next) = read_uleb128(bytes, cursor)?;
            cursor = next;
            validate_index("type", type_idx, type_count)?;
            if address >= insns_size {
                return Err(DexError::InvalidControlFlow {
                    offset: 0,
                    target: i64::from(address),
                });
            }
            typed_handlers.push((type_idx, address));
        }

        let catch_all_addr = if signed_size <= 0 {
            let (address, next) = read_uleb128(bytes, cursor)?;
            cursor = next;
            if address >= insns_size {
                return Err(DexError::InvalidControlFlow {
                    offset: 0,
                    target: i64::from(address),
                });
            }
            Some(address)
        } else {
            None
        };

        result.push(CatchHandler {
            relative_offset,
            typed_handlers,
            catch_all_addr,
        });
    }

    Ok(result)
}

fn decode_instructions(
    units: &[u16],
    string_count: usize,
    type_count: usize,
    field_count: usize,
    method_count: usize,
    proto_count: usize,
) -> Result<Vec<Instruction>> {
    let mut instructions = Vec::new();
    let mut offset = 0_usize;

    while offset < units.len() {
        let unit = units[offset];
        if matches!(unit, 0x0100 | 0x0200 | 0x0300) {
            let (pseudo, width) = payload_width(units, offset)?;
            instructions.push(Instruction {
                offset: offset as u32,
                opcode: 0,
                width,
                pseudo: Some(pseudo),
                branch_targets: Vec::new(),
                reference: None,
                secondary_reference: None,
            });
            offset += width as usize;
            continue;
        }

        let opcode = (unit & 0x00ff) as u8;
        let width = opcode_width(opcode).ok_or(DexError::UnsupportedOpcode {
            opcode,
            offset: offset as u32,
        })?;
        if offset + width as usize > units.len() {
            return Err(DexError::InvalidInstruction {
                offset: offset as u32,
                reason: format!("opcode 0x{opcode:02x} overruns code_item"),
            });
        }

        let (reference, secondary_reference) = instruction_references(units, offset, opcode)?;
        if let Some((kind, index)) = reference {
            validate_reference(
                kind,
                index,
                string_count,
                type_count,
                field_count,
                method_count,
                proto_count,
            )?;
        }
        if let Some((kind, index)) = secondary_reference {
            validate_reference(
                kind,
                index,
                string_count,
                type_count,
                field_count,
                method_count,
                proto_count,
            )?;
        }

        let branch_targets = branch_targets(units, offset, opcode)?;
        instructions.push(Instruction {
            offset: offset as u32,
            opcode,
            width,
            pseudo: None,
            branch_targets,
            reference,
            secondary_reference,
        });
        offset += width as usize;
    }

    let boundaries = instructions
        .iter()
        .map(|instruction| instruction.offset)
        .collect::<BTreeSet<_>>();

    for instruction in &instructions {
        for target in &instruction.branch_targets {
            if !boundaries.contains(target) {
                return Err(DexError::InvalidControlFlow {
                    offset: instruction.offset,
                    target: i64::from(*target),
                });
            }
        }
    }

    Ok(instructions)
}

fn opcode_width(opcode: u8) -> Option<u32> {
    match opcode {
        0x00
        | 0x01
        | 0x04
        | 0x07
        | 0x0a..=0x12
        | 0x1d
        | 0x1e
        | 0x21
        | 0x27
        | 0x28
        | 0x7b..=0x8f
        | 0xb0..=0xcf => Some(1),
        0x02
        | 0x05
        | 0x08
        | 0x13
        | 0x15
        | 0x16
        | 0x19
        | 0x1a
        | 0x1c
        | 0x1f
        | 0x20
        | 0x22
        | 0x23
        | 0x29
        | 0x2d..=0x3d
        | 0x44..=0x6d
        | 0x90..=0xaf
        | 0xd0..=0xe2
        | 0xfe
        | 0xff => Some(2),
        0x03
        | 0x06
        | 0x09
        | 0x14
        | 0x17
        | 0x1b
        | 0x24
        | 0x25
        | 0x26
        | 0x2a..=0x2c
        | 0x6e..=0x72
        | 0x74..=0x78
        | 0xfc
        | 0xfd => Some(3),
        0x18 => Some(5),
        0xfa | 0xfb => Some(4),
        _ => None,
    }
}

fn payload_width(units: &[u16], offset: usize) -> Result<(PseudoInstruction, u32)> {
    match units[offset] {
        0x0100 => {
            let size = usize::from(*units.get(offset + 1).ok_or_else(|| {
                DexError::InvalidInstruction {
                    offset: offset as u32,
                    reason: "truncated packed-switch payload".into(),
                }
            })?);
            let width = 4_usize
                .checked_add(
                    size.checked_mul(2)
                        .ok_or_else(|| DexError::InvalidInstruction {
                            offset: offset as u32,
                            reason: "packed-switch payload size overflow".into(),
                        })?,
                )
                .ok_or_else(|| DexError::InvalidInstruction {
                    offset: offset as u32,
                    reason: "packed-switch payload width overflow".into(),
                })?;
            ensure_units(units, offset, width, "packed-switch payload")?;
            Ok((PseudoInstruction::PackedSwitchPayload, width as u32))
        }
        0x0200 => {
            let size = usize::from(*units.get(offset + 1).ok_or_else(|| {
                DexError::InvalidInstruction {
                    offset: offset as u32,
                    reason: "truncated sparse-switch payload".into(),
                }
            })?);
            let width = 2_usize
                .checked_add(
                    size.checked_mul(4)
                        .ok_or_else(|| DexError::InvalidInstruction {
                            offset: offset as u32,
                            reason: "sparse-switch payload size overflow".into(),
                        })?,
                )
                .ok_or_else(|| DexError::InvalidInstruction {
                    offset: offset as u32,
                    reason: "sparse-switch payload width overflow".into(),
                })?;
            ensure_units(units, offset, width, "sparse-switch payload")?;
            Ok((PseudoInstruction::SparseSwitchPayload, width as u32))
        }
        0x0300 => {
            ensure_units(units, offset, 4, "fill-array-data payload header")?;
            let element_width = usize::from(units[offset + 1]);
            let size = usize::try_from(read_u32_units(units, offset + 2)?).map_err(|_| {
                DexError::InvalidInstruction {
                    offset: offset as u32,
                    reason: "fill-array-data element count does not fit host".into(),
                }
            })?;
            let bytes =
                element_width
                    .checked_mul(size)
                    .ok_or_else(|| DexError::InvalidInstruction {
                        offset: offset as u32,
                        reason: "fill-array-data byte size overflow".into(),
                    })?;
            let payload_units =
                bytes
                    .checked_add(1)
                    .ok_or_else(|| DexError::InvalidInstruction {
                        offset: offset as u32,
                        reason: "fill-array-data width overflow".into(),
                    })?
                    / 2;
            let width =
                4_usize
                    .checked_add(payload_units)
                    .ok_or_else(|| DexError::InvalidInstruction {
                        offset: offset as u32,
                        reason: "fill-array-data width overflow".into(),
                    })?;
            ensure_units(units, offset, width, "fill-array-data payload")?;
            Ok((PseudoInstruction::FillArrayDataPayload, width as u32))
        }
        _ => Err(DexError::InvalidInstruction {
            offset: offset as u32,
            reason: "unknown pseudo-instruction payload".into(),
        }),
    }
}

type InstructionReference = Option<(ReferenceKind, u32)>;
type InstructionReferences = (InstructionReference, InstructionReference);

fn instruction_references(
    units: &[u16],
    offset: usize,
    opcode: u8,
) -> Result<InstructionReferences> {
    let unit1 = || -> Result<u32> {
        units
            .get(offset + 1)
            .copied()
            .map(u32::from)
            .ok_or_else(|| DexError::InvalidInstruction {
                offset: offset as u32,
                reason: "missing reference code unit".into(),
            })
    };

    let result = match opcode {
        0x1a => (Some((ReferenceKind::String, unit1()?)), None),
        0x1b => (
            Some((ReferenceKind::String, read_u32_units(units, offset + 1)?)),
            None,
        ),
        0x1c | 0x1f | 0x20 | 0x22 | 0x23 | 0x24 | 0x25 => {
            (Some((ReferenceKind::Type, unit1()?)), None)
        }
        0x52..=0x6d => (Some((ReferenceKind::Field, unit1()?)), None),
        0x6e..=0x72 | 0x74..=0x78 => (Some((ReferenceKind::Method, unit1()?)), None),
        0xfa | 0xfb => {
            let proto = units
                .get(offset + 3)
                .copied()
                .map(u32::from)
                .ok_or_else(|| DexError::InvalidInstruction {
                    offset: offset as u32,
                    reason: "missing invoke-polymorphic proto reference".into(),
                })?;
            (
                Some((ReferenceKind::Method, unit1()?)),
                Some((ReferenceKind::Proto, proto)),
            )
        }
        0xfc | 0xfd => (Some((ReferenceKind::CallSite, unit1()?)), None),
        0xfe => (Some((ReferenceKind::MethodHandle, unit1()?)), None),
        0xff => (Some((ReferenceKind::Proto, unit1()?)), None),
        _ => (None, None),
    };
    Ok(result)
}

fn validate_reference(
    kind: ReferenceKind,
    index: u32,
    string_count: usize,
    type_count: usize,
    field_count: usize,
    method_count: usize,
    proto_count: usize,
) -> Result<()> {
    match kind {
        ReferenceKind::String => validate_index("string", index, string_count),
        ReferenceKind::Type => validate_index("type", index, type_count),
        ReferenceKind::Field => validate_index("field", index, field_count),
        ReferenceKind::Method => validate_index("method", index, method_count),
        ReferenceKind::Proto => validate_index("proto", index, proto_count),
        ReferenceKind::CallSite | ReferenceKind::MethodHandle => Ok(()),
    }
}

fn branch_targets(units: &[u16], offset: usize, opcode: u8) -> Result<Vec<u32>> {
    match opcode {
        0x28 => {
            let delta = i8::from_ne_bytes([(units[offset] >> 8) as u8]);
            Ok(vec![checked_target(offset, i64::from(delta))?])
        }
        0x29 | 0x32..=0x3d => {
            let delta = i16::from_le_bytes(units[offset + 1].to_le_bytes());
            Ok(vec![checked_target(offset, i64::from(delta))?])
        }
        0x2a => {
            let raw = read_u32_units(units, offset + 1)?;
            let delta = i32::from_le_bytes(raw.to_le_bytes());
            Ok(vec![checked_target(offset, i64::from(delta))?])
        }
        0x2b | 0x2c => {
            let raw = read_u32_units(units, offset + 1)?;
            let payload_delta = i32::from_le_bytes(raw.to_le_bytes());
            let payload = checked_target(offset, i64::from(payload_delta))? as usize;
            parse_switch_targets(units, offset, payload, opcode)
        }
        _ => Ok(Vec::new()),
    }
}

fn parse_switch_targets(
    units: &[u16],
    switch_offset: usize,
    payload_offset: usize,
    opcode: u8,
) -> Result<Vec<u32>> {
    let expected = if opcode == 0x2b { 0x0100 } else { 0x0200 };
    if units.get(payload_offset).copied() != Some(expected) {
        return Err(DexError::InvalidInstruction {
            offset: switch_offset as u32,
            reason: format!("switch payload at {payload_offset} has wrong identifier"),
        });
    }
    let size = usize::from(*units.get(payload_offset + 1).ok_or_else(|| {
        DexError::InvalidInstruction {
            offset: switch_offset as u32,
            reason: "truncated switch payload".into(),
        }
    })?);

    let targets_start = if opcode == 0x2b {
        payload_offset + 4
    } else {
        payload_offset + 2 + size * 2
    };
    ensure_units(units, targets_start, size * 2, "switch targets")?;

    let mut targets = Vec::with_capacity(size);
    for index in 0..size {
        let raw = read_u32_units(units, targets_start + index * 2)?;
        let delta = i32::from_le_bytes(raw.to_le_bytes());
        targets.push(checked_target(switch_offset, i64::from(delta))?);
    }
    Ok(targets)
}

fn checked_target(origin: usize, delta: i64) -> Result<u32> {
    let target = i64::try_from(origin)
        .ok()
        .and_then(|base| base.checked_add(delta))
        .ok_or(DexError::InvalidControlFlow {
            offset: origin as u32,
            target: delta,
        })?;
    if target < 0 || target > i64::from(u32::MAX) {
        return Err(DexError::InvalidControlFlow {
            offset: origin as u32,
            target,
        });
    }
    Ok(target as u32)
}

fn read_u32_units(units: &[u16], offset: usize) -> Result<u32> {
    let low = *units
        .get(offset)
        .ok_or_else(|| DexError::InvalidInstruction {
            offset: offset as u32,
            reason: "missing low 16-bit code unit".into(),
        })?;
    let high = *units
        .get(offset + 1)
        .ok_or_else(|| DexError::InvalidInstruction {
            offset: offset as u32,
            reason: "missing high 16-bit code unit".into(),
        })?;
    Ok(u32::from(low) | (u32::from(high) << 16))
}

fn read_uleb128(bytes: &[u8], offset: usize) -> Result<(u32, usize)> {
    let mut result = 0_u32;
    let mut cursor = offset;
    for shift in [0_u32, 7, 14, 21, 28] {
        let byte = *bytes
            .get(cursor)
            .ok_or(DexError::InvalidLeb128 { offset })?;
        cursor += 1;
        if shift == 28 && byte & 0xf0 != 0 {
            return Err(DexError::InvalidLeb128 { offset });
        }
        result |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, cursor));
        }
    }
    Err(DexError::InvalidLeb128 { offset })
}

fn read_sleb128(bytes: &[u8], offset: usize) -> Result<(i32, usize)> {
    let mut result = 0_i32;
    let mut cursor = offset;
    let mut shift = 0_u32;

    for _ in 0..5 {
        let byte = *bytes
            .get(cursor)
            .ok_or(DexError::InvalidLeb128 { offset })?;
        cursor += 1;
        result |= i32::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 32 && byte & 0x40 != 0 {
                result |= !0_i32 << shift;
            }
            return Ok((result, cursor));
        }
    }

    Err(DexError::InvalidLeb128 { offset })
}

fn validate_index(kind: &'static str, index: u32, count: usize) -> Result<()> {
    if usize::try_from(index).is_ok_and(|value| value < count) {
        Ok(())
    } else {
        Err(DexError::InvalidIndex { kind, index })
    }
}

fn read_u16(bytes: &[u8], offset: usize, context: &str) -> Result<u16> {
    ensure(bytes, offset, 2, context)?;
    Ok(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
}

fn read_u32(bytes: &[u8], offset: usize, context: &str) -> Result<u32> {
    ensure(bytes, offset, 4, context)?;
    Ok(u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}

fn ensure(bytes: &[u8], offset: usize, length: usize, context: &str) -> Result<()> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| DexError::Truncated {
            context: context.to_owned(),
            offset,
        })?;
    if end > bytes.len() {
        return Err(DexError::Truncated {
            context: context.to_owned(),
            offset,
        });
    }
    Ok(())
}

fn ensure_units(units: &[u16], offset: usize, length: usize, context: &str) -> Result<()> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| DexError::InvalidInstruction {
            offset: offset as u32,
            reason: format!("{context} length overflow"),
        })?;
    if end > units.len() {
        return Err(DexError::InvalidInstruction {
            offset: offset as u32,
            reason: format!("{context} is truncated"),
        });
    }
    Ok(())
}
