//! Strict read-only ELF/JNI export preflight for Phase O.1.3.
//!
//! Native libraries cannot yet be rewritten or authorized by this reader.
//! A valid ELF dynamic symbol table is evidence, not proof that the binary
//! never calls FindClass, RegisterNatives, or other dynamic JNI APIs.
use crate::{CoreError, Result};

const MAX_SECTIONS: usize = 4096;
const MAX_SYMBOLS: usize = 131_072;
const MAX_EXPORT_NAME: usize = 4096;
const SHT_DYNSYM: u32 = 11;
const SHT_STRTAB: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeExports {
    pub(crate) static_jni: Vec<String>,
    pub(crate) has_jni_onload: bool,
}

fn reject(reason: &str) -> CoreError {
    CoreError::InvalidRequest(format!("O.1.3 native ELF/JNI: {reason}"))
}

fn area(data: &[u8], at: usize, size: usize) -> Result<&[u8]> {
    let end = at
        .checked_add(size)
        .ok_or_else(|| reject("offset overflow"))?;
    data.get(at..end)
        .ok_or_else(|| reject("section or symbol is truncated"))
}

fn number16(data: &[u8], at: usize) -> Result<u16> {
    let raw = area(data, at, 2)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn number32(data: &[u8], at: usize) -> Result<u32> {
    let raw = area(data, at, 4)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn number64(data: &[u8], at: usize) -> Result<u64> {
    let raw = area(data, at, 8)?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

fn word(data: &[u8], at: usize, wide: bool) -> Result<usize> {
    if wide {
        usize::try_from(number64(data, at)?).map_err(|_| reject("64-bit offset overflow"))
    } else {
        usize::try_from(number32(data, at)?).map_err(|_| reject("32-bit offset overflow"))
    }
}

#[derive(Clone, Copy)]
struct Section {
    kind: u32,
    offset: usize,
    size: usize,
    link: usize,
    stride: usize,
}

fn section(data: &[u8], at: usize, wide: bool) -> Result<Section> {
    let kind = number32(data, at + 4)?;
    let (offset, size, link, stride) = if wide {
        (
            word(data, at + 24, true)?,
            word(data, at + 32, true)?,
            word(data, at + 40, false)?,
            word(data, at + 56, true)?,
        )
    } else {
        (
            word(data, at + 16, false)?,
            word(data, at + 20, false)?,
            word(data, at + 24, false)?,
            word(data, at + 36, false)?,
        )
    };
    // SHT_NOBITS (8) has no file payload, but all linked dynamic sections do.
    if kind != 8 {
        area(data, offset, size)?;
    }
    Ok(Section {
        kind,
        offset,
        size,
        link,
        stride,
    })
}

fn machine_for_apk_path(path: &str) -> Result<u16> {
    match path.split('/').collect::<Vec<_>>().as_slice() {
        ["lib", "arm64-v8a", file] if file.ends_with(".so") => Ok(183),
        ["lib", "armeabi-v7a", file] if file.ends_with(".so") => Ok(40),
        ["lib", "x86_64", file] if file.ends_with(".so") => Ok(62),
        ["lib", "x86", file] if file.ends_with(".so") => Ok(3),
        _ => Err(reject("unsupported native library ABI or archive path")),
    }
}

fn parse_export_name(table: &[u8], index: usize) -> Result<&str> {
    let rest = table
        .get(index..)
        .ok_or_else(|| reject("dynamic symbol name offset outside string table"))?;
    let length = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| reject("unterminated dynamic symbol name"))?;
    if length > MAX_EXPORT_NAME {
        return Err(reject("dynamic symbol name exceeds budget"));
    }
    std::str::from_utf8(&rest[..length]).map_err(|_| reject("invalid UTF-8 dynamic symbol"))
}

fn collect_dynamic_exports(
    bytes: &[u8],
    sections: &[Section],
    wide: bool,
) -> Result<NativeExports> {
    let mut result = NativeExports {
        static_jni: Vec::new(),
        has_jni_onload: false,
    };
    let mut saw_dynamic_symbols = false;
    for symtab in sections.iter().filter(|s| s.kind == SHT_DYNSYM) {
        saw_dynamic_symbols = true;
        let sym_size = if wide { 24 } else { 16 };
        if symtab.stride != sym_size
            || symtab.size % sym_size != 0
            || symtab.size / sym_size > MAX_SYMBOLS
        {
            return Err(reject("invalid dynamic symbol table stride or count"));
        }
        let strings = sections
            .get(symtab.link)
            .filter(|s| s.kind == SHT_STRTAB)
            .ok_or_else(|| reject("dynamic symbol table is not linked to a string table"))?;
        let names = area(bytes, strings.offset, strings.size)?;
        for index in 0..symtab.size / sym_size {
            let at = symtab.offset + index * sym_size;
            let name_offset = word(bytes, at, false)?;
            let info = *area(bytes, at + if wide { 4 } else { 12 }, 1)?
                .first()
                .ok_or_else(|| reject("missing dynamic symbol flags"))?;
            let defined = number16(bytes, at + if wide { 6 } else { 14 })? != 0;
            let global = matches!(info >> 4, 1 | 2);
            let function = matches!(info & 0xf, 0 | 2);
            if !defined || !global || !function || name_offset == 0 {
                continue;
            }
            let name = parse_export_name(names, name_offset)?;
            if name == "JNI_OnLoad" {
                result.has_jni_onload = true;
            } else if name.starts_with("Java_") {
                result.static_jni.push(name.to_owned());
            }
        }
    }
    if !saw_dynamic_symbols {
        return Err(reject("missing section-backed dynamic symbol table"));
    }
    result.static_jni.sort();
    result.static_jni.dedup();
    Ok(result)
}

/// Parse an Android ELF shared object and collect exported static JNI names.
///
/// A successful inspection does NOT authorize native ABI rewriting.
///
/// # Errors
///
/// Refuses unsupported ABI paths, non-little-endian or non-ET_DYN ELF, missing
/// dynamic symbol tables, malformed bounds, and invalid symbol name offsets.
pub(crate) fn inspect_native_elf(bytes: &[u8], path: &str) -> Result<NativeExports> {
    if bytes.len() < 52 || area(bytes, 0, 4)? != b"\x7fELF" {
        return Err(reject("not a complete ELF shared object"));
    }
    let class = bytes[4];
    let wide = match class {
        1 => false,
        2 => true,
        _ => return Err(reject("unsupported ELF word size")),
    };
    if bytes[5] != 1 || bytes[6] != 1 {
        return Err(reject("ELF must be little-endian version one"));
    }
    let header_size = if wide { 64 } else { 52 };
    area(bytes, 0, header_size)?;
    if number16(bytes, 16)? != 3
        || number16(bytes, 18)? != machine_for_apk_path(path)?
        || number32(bytes, 20)? != 1
        || usize::from(number16(bytes, if wide { 52 } else { 40 })?) != header_size
    {
        return Err(reject("ELF type, machine, version or header mismatch"));
    }
    let sections_offset = word(bytes, if wide { 40 } else { 32 }, wide)?;
    let count = usize::from(number16(bytes, if wide { 60 } else { 48 })?);
    let stride = usize::from(number16(bytes, if wide { 58 } else { 46 })?);
    let expected = if wide { 64 } else { 40 };
    if count == 0 || count > MAX_SECTIONS || stride != expected || sections_offset < header_size {
        return Err(reject("unsupported or missing section header table"));
    }
    let total = count
        .checked_mul(stride)
        .ok_or_else(|| reject("section header table overflow"))?;
    area(bytes, sections_offset, total)?;
    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        sections.push(section(bytes, sections_offset + index * stride, wide)?);
    }
    collect_dynamic_exports(bytes, &sections, wide)
}

/// Check whether an unchanged static JNI export still refers to a class
/// descriptor that the DEX rewrite proposes to rename.
///
/// JNI mangle escaping is applied to the class name, not a raw substring:
/// underscores must be encoded as `_1` and package separators as `_`.
pub(crate) fn references_renamed_class(export: &str, old_descriptor: &str) -> bool {
    let Some(class) = old_descriptor
        .strip_prefix('L')
        .and_then(|value| value.strip_suffix(';'))
    else {
        return false;
    };
    let mut prefix = String::from("Java_");
    for ch in class.chars() {
        match ch {
            '/' => prefix.push('_'),
            '_' => prefix.push_str("_1"),
            ';' => prefix.push_str("_2"),
            '[' => prefix.push_str("_3"),
            ch => prefix.push(ch),
        }
    }
    prefix.push('_');
    export.starts_with(&prefix)
}

#[cfg(test)]
mod tests {
    use super::{inspect_native_elf, references_renamed_class};

    fn write16(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn write32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn write64(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn sample(wide: bool) -> Vec<u8> {
        let header = if wide { 64 } else { 52 };
        let entry = if wide { 24 } else { 16 };
        let section = if wide { 64 } else { 40 };
        let names = b"\0Java_com_test_A_run\0JNI_OnLoad\0";
        let dynstr = header;
        let dynsym = dynstr + names.len();
        let headers = dynsym + 3 * entry;
        let mut bytes = vec![0_u8; headers + 3 * section];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = if wide { 2 } else { 1 };
        bytes[5] = 1;
        bytes[6] = 1;
        write16(&mut bytes, 16, 3);
        write16(&mut bytes, 18, if wide { 183 } else { 40 });
        write32(&mut bytes, 20, 1);
        write16(
            &mut bytes,
            if wide { 52 } else { 40 },
            u16::try_from(header).unwrap_or(0),
        );
        write16(
            &mut bytes,
            if wide { 58 } else { 46 },
            u16::try_from(section).unwrap_or(0),
        );
        write16(&mut bytes, if wide { 60 } else { 48 }, 3);
        if wide {
            write64(&mut bytes, 40, u64::try_from(headers).unwrap_or(0));
        } else {
            write32(&mut bytes, 32, u32::try_from(headers).unwrap_or(0));
        }
        bytes[dynstr..dynstr + names.len()].copy_from_slice(names);
        for (index, name_at) in [1, 1 + 20].iter().enumerate() {
            let at = dynsym + (index + 1) * entry;
            write32(&mut bytes, at, *name_at);
            bytes[at + if wide { 4 } else { 12 }] = 0x12;
            write16(&mut bytes, at + if wide { 6 } else { 14 }, 1);
        }
        let sym = headers + section;
        let strings = headers + section * 2;
        write32(&mut bytes, sym + 4, 11);
        write32(&mut bytes, strings + 4, 3);
        if wide {
            write64(&mut bytes, sym + 24, u64::try_from(dynsym).unwrap_or(0));
            write64(&mut bytes, sym + 32, u64::try_from(3 * entry).unwrap_or(0));
            write32(&mut bytes, sym + 40, 2);
            write64(&mut bytes, sym + 56, u64::try_from(entry).unwrap_or(0));
            write64(&mut bytes, strings + 24, u64::try_from(dynstr).unwrap_or(0));
            write64(
                &mut bytes,
                strings + 32,
                u64::try_from(names.len()).unwrap_or(0),
            );
        } else {
            write32(&mut bytes, sym + 16, u32::try_from(dynsym).unwrap_or(0));
            write32(&mut bytes, sym + 20, u32::try_from(3 * entry).unwrap_or(0));
            write32(&mut bytes, sym + 24, 2);
            write32(&mut bytes, sym + 36, u32::try_from(entry).unwrap_or(0));
            write32(&mut bytes, strings + 16, u32::try_from(dynstr).unwrap_or(0));
            write32(
                &mut bytes,
                strings + 20,
                u32::try_from(names.len()).unwrap_or(0),
            );
        }
        bytes
    }

    #[test]
    fn o13_jni_inspects_arm64_and_arm32_dynamic_exports() {
        for (wide, path) in [
            (true, "lib/arm64-v8a/libsample.so"),
            (false, "lib/armeabi-v7a/libsample.so"),
        ] {
            let bytes = sample(wide);
            let report = inspect_native_elf(&bytes, path).ok();
            assert!(report.as_ref().is_some_and(|value| {
                value.static_jni == ["Java_com_test_A_run"] && value.has_jni_onload
            }));
        }
    }

    #[test]
    fn o13_jni_detects_class_rename_and_jni_escape_boundaries() {
        assert!(references_renamed_class(
            "Java_com_test_A_run",
            "Lcom/test/A;"
        ));
        assert!(references_renamed_class(
            "Java_com_my_1app_A_do_1work",
            "Lcom/my_app/A;"
        ));
        assert!(!references_renamed_class(
            "Java_com_test_Another_run",
            "Lcom/test/A;"
        ));
        assert!(!references_renamed_class(
            "Java_com_test_A2_run",
            "Lcom/test/A;"
        ));
    }

    #[test]
    fn o13_jni_rejects_truncated_wrong_arch_and_unlinked_tables() {
        for (wide, path) in [
            (true, "lib/arm64-v8a/libsample.so"),
            (false, "lib/armeabi-v7a/libsample.so"),
        ] {
            let valid = sample(wide);
            for limit in [0, 4, 31, valid.len() - 1] {
                assert!(inspect_native_elf(&valid[..limit], path).is_err());
            }
            let wrong_path = if wide {
                "lib/x86_64/libsample.so"
            } else {
                "lib/x86/libsample.so"
            };
            assert!(inspect_native_elf(&valid, wrong_path).is_err());
            let mut bad = valid.clone();
            let symbol_headers = if wide {
                u64::from_le_bytes(bad[40..48].try_into().unwrap_or([0; 8])) as usize
            } else {
                u32::from_le_bytes(bad[32..36].try_into().unwrap_or([0; 4])) as usize
            };
            let offset = symbol_headers + if wide { 64 + 40 } else { 40 + 24 };
            write32(&mut bad, offset, 42);
            assert!(inspect_native_elf(&bad, path).is_err());
        }
    }
}
