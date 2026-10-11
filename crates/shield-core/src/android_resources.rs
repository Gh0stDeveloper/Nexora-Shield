//! Bounded, read-only Android Resource Table (resources.arsc) inspection.
//! O.1.3: structural validation and string-link auditing, NOT resource ID
//! relocation, string rewriting, APK installability, or production protection.
use crate::{android_binary_xml::inspect_string_pool, CoreError, Result};
use std::collections::BTreeMap;

const TABLE: u16 = 0x0002;
const POOL: u16 = 0x0001;
const PACKAGE: u16 = 0x0200;
const TYPE: u16 = 0x0201;
const TYPE_SPEC: u16 = 0x0202;
const MAX_CHUNKS: usize = 65_536;
const MAX_ENTRIES: usize = 65_536;
const NO_ENTRY: u32 = u32::MAX;
const FLAG_COMPLEX: u16 = 0x0001;
const FLAG_SPARSE: u8 = 0x01;
const FLAG_OFFSET16: u8 = 0x02;
const TYPE_STRING: u8 = 0x03;

fn reject(reason: &str) -> CoreError {
    CoreError::InvalidRequest(format!("O.1.3 resources.arsc: {reason}"))
}

fn range(data: &[u8], at: usize, size: usize) -> Result<&[u8]> {
    let end = at
        .checked_add(size)
        .ok_or_else(|| reject("offset overflow"))?;
    data.get(at..end).ok_or_else(|| reject("truncated table"))
}

fn le16(data: &[u8], at: usize) -> Result<u16> {
    let bytes = range(data, at, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le32(data: &[u8], at: usize) -> Result<u32> {
    let bytes = range(data, at, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn word(data: &[u8], at: usize) -> Result<usize> {
    usize::try_from(le32(data, at)?).map_err(|_| reject("word-size overflow"))
}

#[derive(Clone, Copy, Debug)]
struct Chunk {
    kind: u16,
    header: usize,
    size: usize,
}

fn chunk(data: &[u8], at: usize) -> Result<Chunk> {
    let kind = le16(data, at)?;
    let header = usize::from(le16(data, at + 2)?);
    let size = word(data, at + 4)?;
    if header < 8 || header > size || at.checked_add(size).map_or(true, |end| end > data.len()) {
        return Err(reject("invalid chunk header or length"));
    }
    Ok(Chunk { kind, header, size })
}

fn pool(data: &[u8], at: usize) -> Result<Vec<String>> {
    let item = chunk(data, at)?;
    inspect_string_pool(range(data, at, item.size)?)
}

fn validate_value(data: &[u8], at: usize, global_strings: usize) -> Result<()> {
    if le16(data, at)? != 8 || data.get(at + 2) != Some(&0) {
        return Err(reject("malformed typed resource value"));
    }
    if data.get(at + 3) == Some(&TYPE_STRING) && word(data, at + 4)? >= global_strings {
        return Err(reject("typed value string index is out of bounds"));
    }
    Ok(())
}

fn validate_entry(
    data: &[u8],
    at: usize,
    limit: usize,
    key_count: usize,
    global: usize,
) -> Result<()> {
    let size = usize::from(le16(data, at)?);
    let flags = le16(data, at + 2)?;
    let key = word(data, at + 4)?;
    if size < 8 || key >= key_count || at.checked_add(size).map_or(true, |end| end > limit) {
        return Err(reject("entry header/key index is invalid"));
    }
    let payload = at + size;
    if flags & FLAG_COMPLEX == 0 {
        if payload.checked_add(8).map_or(true, |end| end > limit) {
            return Err(reject("simple entry value is truncated"));
        }
        validate_value(data, payload, global)
    } else {
        if size < 16 {
            return Err(reject("complex resource entry header is incomplete"));
        }
        let count = word(data, at + 12)?;
        if count > MAX_ENTRIES
            || count
                .checked_mul(12)
                .and_then(|size| payload.checked_add(size))
                .map_or(true, |end| end > limit)
        {
            return Err(reject("complex resource maps exceed entry bounds"));
        }
        for n in 0..count {
            let map = payload + n * 12;
            let _name_reference = le32(data, map)?;
            validate_value(data, map + 4, global)?;
        }
        Ok(())
    }
}

fn validate_type(
    data: &[u8],
    item: Chunk,
    id: u8,
    spec_count: usize,
    type_count: usize,
    key_count: usize,
    global: usize,
) -> Result<()> {
    if item.header < 24 || item.size < item.header || id == 0 || usize::from(id) > type_count {
        return Err(reject("resource type header/name is invalid"));
    }
    let flags = *range(data, 9, 1)?
        .first()
        .ok_or_else(|| reject("type flags missing"))?;
    if flags & !(FLAG_SPARSE | FLAG_OFFSET16) != 0 || flags == (FLAG_SPARSE | FLAG_OFFSET16) {
        return Err(reject("unsupported resource type offset encoding"));
    }
    let entry_count = word(data, 12)?;
    let entries_start = word(data, 16)?;
    let config_size = word(data, 20)?;
    if entry_count > MAX_ENTRIES
        || (flags & FLAG_SPARSE == 0 && entry_count != spec_count)
        || config_size < 4
        || 20_usize
            .checked_add(config_size)
            .map_or(true, |end| end > item.header)
        || entries_start > item.size
        || entries_start % 4 != 0
    {
        return Err(reject("resource type config or entry count invalid"));
    }
    let stride = if flags & FLAG_OFFSET16 != 0 { 2 } else { 4 };
    if item
        .header
        .checked_add(entry_count * stride)
        .map_or(true, |end| end > entries_start)
    {
        return Err(reject("resource entry offset table overlaps payload"));
    }

    let mut prev = None;
    for index in 0..entry_count {
        let offset = item.header + index * stride;
        let (entry_idx, data_off) = if flags & FLAG_SPARSE != 0 {
            let idx = usize::from(le16(data, offset)?);
            let scaled = usize::from(le16(data, offset + 2)?) * 4;
            if idx >= spec_count || prev.is_some_and(|old| idx <= old) {
                return Err(reject("sparse resource indices not sorted or out of range"));
            }
            prev = Some(idx);
            (idx, Some(scaled))
        } else if flags & FLAG_OFFSET16 != 0 {
            let value = le16(data, offset)?;
            (index, (value != u16::MAX).then_some(usize::from(value) * 4))
        } else {
            let value = le32(data, offset)?;
            (
                index,
                (value != NO_ENTRY).then_some(
                    usize::try_from(value).map_err(|_| reject("entry offset overflow"))?,
                ),
            )
        };
        let _ = entry_idx;
        if let Some(entry_off) = data_off {
            let entry_at = entries_start
                .checked_add(entry_off)
                .ok_or_else(|| reject("resource entry offset overflow"))?;
            if entry_at < entries_start
                || entry_at.checked_add(8).map_or(true, |end| end > item.size)
            {
                return Err(reject("resource entry outside payload"));
            }
            validate_entry(data, entry_at, item.size, key_count, global)?;
        }
    }
    Ok(())
}

fn inspect_package(data: &[u8], item: Chunk, global: usize) -> Result<Vec<String>> {
    // ResTable_package is 284 bytes through Android O, or 288 with typeIdOffset.
    if !matches!(item.header, 284 | 288) {
        return Err(reject("unsupported package header layout"));
    }
    let type_at = word(data, 268)?;
    let key_at = word(data, 276)?;
    if type_at < item.header
        || key_at < item.header
        || type_at >= item.size
        || key_at >= item.size
        || type_at % 4 != 0
        || key_at % 4 != 0
        || type_at == key_at
    {
        return Err(reject("package string pool offsets invalid"));
    }
    let types = pool(data, type_at)?;
    let keys = pool(data, key_at)?;
    let mut seen_types = false;
    let mut seen_keys = false;
    let mut specs = BTreeMap::new();
    let mut offset = item.header;
    let mut chunks = 0_usize;
    while offset < data.len() {
        chunks += 1;
        if chunks > MAX_CHUNKS {
            return Err(reject("package chunk count exceeds budget"));
        }
        let child = chunk(data, offset)?;
        match child.kind {
            POOL if offset == type_at && !seen_types => seen_types = true,
            POOL if offset == key_at && !seen_keys => seen_keys = true,
            TYPE_SPEC => {
                if child.header != 16 {
                    return Err(reject("malformed type specification"));
                }
                let id = *range(data, offset + 8, 1)?
                    .first()
                    .ok_or_else(|| reject("missing type id"))?;
                let count = word(data, offset + 12)?;
                if id == 0
                    || usize::from(id) > types.len()
                    || count > MAX_ENTRIES
                    || child
                        .header
                        .checked_add(count * 4)
                        .map_or(true, |end| end > child.size)
                    || specs.insert(id, count).is_some()
                {
                    return Err(reject("type specification index/count invalid"));
                }
            }
            TYPE => {
                let id = *range(data, offset + 8, 1)?
                    .first()
                    .ok_or_else(|| reject("missing type id"))?;
                let spec = specs
                    .get(&id)
                    .copied()
                    .ok_or_else(|| reject("type has no preceding specification"))?;
                validate_type(
                    range(data, offset, child.size)?,
                    child,
                    id,
                    spec,
                    types.len(),
                    keys.len(),
                    global,
                )?;
            }
            _ => {
                return Err(reject(
                    "unsupported package chunk; resource linking requires a verified parser",
                ))
            }
        }
        offset = offset
            .checked_add(child.size)
            .ok_or_else(|| reject("package offset overflow"))?;
    }
    if offset != data.len() || !seen_types || !seen_keys {
        return Err(reject("incomplete package or unmatched string pools"));
    }
    let mut names = types;
    names.extend(keys);
    Ok(names)
}

/// Inspect a resources.arsc table without changing resource IDs, string pool
/// offsets, values, or packages. Unknown layouts fail closed.
///
/// # Errors
///
/// Rejects invalid bounds, string references, type layouts and package counts.
pub(crate) fn inspect_resource_table(bytes: &[u8]) -> Result<Vec<String>> {
    let root = chunk(bytes, 0)?;
    if root.kind != TABLE || root.header != 12 || root.size != bytes.len() {
        return Err(reject("invalid resource table root"));
    }
    let packages = word(bytes, 8)?;
    if packages > 256 {
        return Err(reject("package count exceeds budget"));
    }
    let mut package_count = 0_usize;
    let mut global = None;
    let mut collected = Vec::new();
    let mut offset = root.header;
    let mut chunks = 0_usize;
    while offset < bytes.len() {
        chunks += 1;
        if chunks > MAX_CHUNKS {
            return Err(reject("table chunk count exceeds budget"));
        }
        let child = chunk(bytes, offset)?;
        match child.kind {
            POOL if global.is_none() && package_count == 0 => {
                let strings = pool(bytes, offset)?;
                collected.extend(strings.iter().cloned());
                global = Some(strings.len());
            }
            PACKAGE if global.is_some() => {
                let strings = inspect_package(
                    range(bytes, offset, child.size)?,
                    child,
                    global.unwrap_or(0),
                )?;
                collected.extend(strings);
                package_count += 1;
            }
            _ => return Err(reject("unsupported resource table chunk/order")),
        }
        offset = offset
            .checked_add(child.size)
            .ok_or_else(|| reject("root offset overflow"))?;
    }
    if offset != bytes.len() || global.is_none() || packages != package_count {
        return Err(reject(
            "resource table package count or global pool mismatch",
        ));
    }
    Ok(collected)
}

// Narrow, offset-preserving resource string-value linker. This does not
// rename resource IDs, resource entry names, file paths or arbitrary chunks.
fn type_string_value(
    data: &[u8],
    at: usize,
    refs: &mut std::collections::BTreeSet<usize>,
) -> Result<()> {
    if data.get(at + 3) == Some(&TYPE_STRING) {
        refs.insert(word(data, at + 4)?);
    }
    Ok(())
}

fn package_string_value_refs(
    pkg: &[u8],
    refs: &mut std::collections::BTreeSet<usize>,
) -> Result<()> {
    let header = chunk(pkg, 0)?.header;
    let mut at = header;
    while at < pkg.len() {
        let item = chunk(pkg, at)?;
        if item.kind == TYPE {
            let data = range(pkg, at, item.size)?;
            let flags = *range(data, 9, 1)?
                .first()
                .ok_or_else(|| reject("missing type flags"))?;
            let count = word(data, 12)?;
            let entries_start = word(data, 16)?;
            let stride = if flags & FLAG_OFFSET16 != 0 { 2 } else { 4 };
            for i in 0..count {
                let pos = item.header + i * stride;
                let entry_offset = if flags & FLAG_SPARSE != 0 {
                    Some(usize::from(le16(data, pos + 2)?) * 4)
                } else if flags & FLAG_OFFSET16 != 0 {
                    let offset = le16(data, pos)?;
                    (offset != u16::MAX).then_some(usize::from(offset) * 4)
                } else {
                    let offset = le32(data, pos)?;
                    (offset != NO_ENTRY).then_some(
                        usize::try_from(offset).map_err(|_| reject("resource offset overflow"))?,
                    )
                };
                if let Some(offset) = entry_offset {
                    let entry_at = entries_start
                        .checked_add(offset)
                        .ok_or_else(|| reject("resource entry offset overflow"))?;
                    let entry_size = usize::from(le16(data, entry_at)?);
                    let flags = le16(data, entry_at + 2)?;
                    let value = entry_at
                        .checked_add(entry_size)
                        .ok_or_else(|| reject("resource entry payload overflow"))?;
                    if flags & FLAG_COMPLEX == 0 {
                        type_string_value(data, value, refs)?;
                    } else {
                        let maps = word(data, entry_at + 12)?;
                        for n in 0..maps {
                            type_string_value(data, value + n * 12 + 4, refs)?;
                        }
                    }
                }
            }
        }
        at += item.size;
    }
    Ok(())
}

fn used_global_string_indices(bytes: &[u8]) -> Result<std::collections::BTreeSet<usize>> {
    let mut refs = std::collections::BTreeSet::new();
    let mut at = 12;
    while at < bytes.len() {
        let item = chunk(bytes, at)?;
        if item.kind == PACKAGE {
            package_string_value_refs(range(bytes, at, item.size)?, &mut refs)?;
        }
        at += item.size;
    }
    Ok(refs)
}

fn string_payload_offset(pool: &[u8], index: usize) -> Result<(usize, bool)> {
    let item = chunk(pool, 0)?;
    let flags = le32(pool, 16)?;
    let strings_start = word(pool, 20)?;
    let off = word(pool, item.header + index * 4)?;
    let pos = strings_start
        .checked_add(off)
        .ok_or_else(|| reject("string pool offset overflow"))?;
    Ok((pos, flags & 0x100 != 0))
}

fn encoded_length_8(pool: &[u8], at: &mut usize) -> Result<usize> {
    let first = *range(pool, *at, 1)?
        .first()
        .ok_or_else(|| reject("missing length"))?;
    *at += 1;
    if first & 0x80 == 0 {
        return Ok(usize::from(first));
    }
    let second = *range(pool, *at, 1)?
        .first()
        .ok_or_else(|| reject("missing length"))?;
    *at += 1;
    Ok((usize::from(first & 0x7f) << 8) | usize::from(second))
}

fn encoded_length_16(pool: &[u8], at: &mut usize) -> Result<usize> {
    let first = le16(pool, *at)?;
    *at += 2;
    if first & 0x8000 == 0 {
        return Ok(usize::from(first));
    }
    let second = le16(pool, *at)?;
    *at += 2;
    Ok((usize::from(first & 0x7fff) << 16) | usize::from(second))
}

fn overwrite_pool_value(
    output: &mut [u8],
    pool_at: usize,
    index: usize,
    original: &str,
    replacement: &str,
) -> Result<()> {
    let pool_item = chunk(output, pool_at)?;
    let pool_snapshot = range(output, pool_at, pool_item.size)?;
    let (mut at, utf8) = string_payload_offset(pool_snapshot, index)?;
    if utf8 {
        let units = encoded_length_8(pool_snapshot, &mut at)?;
        let count = encoded_length_8(pool_snapshot, &mut at)?;
        if units != original.encode_utf16().count()
            || units != replacement.encode_utf16().count()
            || count != original.len()
            || count != replacement.len()
        {
            return Err(reject(
                "UTF-8 resource replacement changes string pool lengths",
            ));
        }
        range(pool_snapshot, at, count)?;
        let write_at = pool_at + at;
        output[write_at..write_at + count].copy_from_slice(replacement.as_bytes());
    } else {
        let count = encoded_length_16(pool_snapshot, &mut at)?;
        if count != original.encode_utf16().count() || count != replacement.encode_utf16().count() {
            return Err(reject(
                "UTF-16 resource replacement changes string pool lengths",
            ));
        }
        let length = count
            .checked_mul(2)
            .ok_or_else(|| reject("UTF-16 size overflow"))?;
        range(pool_snapshot, at, length)?;
        let write_at = pool_at + at;
        for (i, unit) in replacement.encode_utf16().enumerate() {
            let pos = write_at + i * 2;
            output[pos..pos + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    Ok(())
}

/// Rewrite only class-name values in the global resource string pool when all
/// occurrences are indexed by validated `TYPE_STRING` resource values.
///
/// This preserves all public resource IDs, string indices and chunk offsets.
/// Unsupported layouts, unreferenced aliases and string-length changes fail
/// closed instead of silently producing a broken Android resource table.
///
/// # Errors
///
/// Rejects unsafe string uses, malformed chunks, alias collisions and invalid
/// post-write resource structures.
pub(crate) fn rewrite_resource_string_aliases(
    bytes: &[u8],
    aliases: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let inspected = inspect_resource_table(bytes)?;
    if aliases.is_empty() {
        return Ok(bytes.to_vec());
    }
    let pool_at = 12;
    let global = pool(bytes, pool_at)?;
    let pool_chunk = chunk(bytes, pool_at)?;
    if word(bytes, pool_at + 12)? != 0 {
        return Err(reject(
            "styled global string pool cannot be safely relinked",
        ));
    }
    let targets = global
        .iter()
        .enumerate()
        .filter(|(_, value)| aliases.contains_key(value.as_str()))
        .map(|(index, _)| index)
        .collect::<std::collections::BTreeSet<_>>();
    if targets.is_empty() {
        for value in &inspected[global.len()..] {
            if aliases.contains_key(value) {
                return Err(reject(
                    "resource key/type pool class name needs a dedicated remapper",
                ));
            }
        }
        return Ok(bytes.to_vec());
    }
    let used = used_global_string_indices(bytes)?;
    if targets.iter().any(|index| !used.contains(index)) {
        return Err(reject(
            "unreferenced global pool class alias cannot be safely linked",
        ));
    }
    if inspected[global.len()..]
        .iter()
        .any(|value| aliases.contains_key(value))
    {
        return Err(reject(
            "resource entry name and value aliases must not share a rewrite",
        ));
    }
    let mut out = bytes.to_vec();
    for index in &targets {
        let old = &global[*index];
        let new = aliases
            .get(old)
            .ok_or_else(|| reject("missing resource alias"))?;
        if global
            .iter()
            .enumerate()
            .any(|(n, value)| n != *index && value == new)
        {
            return Err(reject(
                "resource alias collides with another global pool string",
            ));
        }
        overwrite_pool_value(&mut out, pool_at, *index, old, new)?;
    }
    if bytes.len() != out.len() || pool_chunk.size != chunk(&out, pool_at)?.size {
        return Err(reject("resource table changed binary layout"));
    }
    let verified = inspect_resource_table(&out)?;
    for (index, before) in inspected.iter().enumerate() {
        let expected = if targets.contains(&index) {
            aliases.get(before).unwrap_or(before)
        } else {
            before
        };
        if verified.get(index) != Some(expected) {
            return Err(reject("resource table read-back failed"));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::inspect_resource_table;

    fn pool(values: &[&str]) -> Vec<u8> {
        let mut strings = Vec::new();
        let mut indices = Vec::new();
        for value in values {
            indices.extend((u32::try_from(strings.len()).unwrap_or(u32::MAX)).to_le_bytes());
            strings.push(u8::try_from(value.encode_utf16().count()).unwrap_or(0));
            strings.push(u8::try_from(value.len()).unwrap_or(0));
            strings.extend(value.as_bytes());
            strings.push(0);
        }
        let mut out = Vec::new();
        out.extend(1_u16.to_le_bytes());
        out.extend(28_u16.to_le_bytes());
        out.extend(
            (u32::try_from(28 + indices.len() + strings.len()).unwrap_or(u32::MAX)).to_le_bytes(),
        );
        out.extend((u32::try_from(values.len()).unwrap_or(u32::MAX)).to_le_bytes());
        out.extend(0_u32.to_le_bytes());
        out.extend(0x100_u32.to_le_bytes());
        out.extend((u32::try_from(28 + indices.len()).unwrap_or(u32::MAX)).to_le_bytes());
        out.extend(0_u32.to_le_bytes());
        out.extend(indices);
        out.extend(strings);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        let total = u32::try_from(out.len()).unwrap_or(u32::MAX);
        out[4..8].copy_from_slice(&total.to_le_bytes());
        out
    }

    fn sample(value: &str) -> Vec<u8> {
        let global = pool(&[value]);
        let type_pool = pool(&["string"]);
        let key_pool = pool(&["title"]);
        let mut spec = Vec::new();
        spec.extend(0x0202_u16.to_le_bytes());
        spec.extend(16_u16.to_le_bytes());
        spec.extend(20_u32.to_le_bytes());
        spec.extend([1_u8, 0, 0, 0]);
        spec.extend(1_u32.to_le_bytes());
        spec.extend(0_u32.to_le_bytes());
        let mut typ = Vec::new();
        typ.extend(0x0201_u16.to_le_bytes());
        typ.extend(24_u16.to_le_bytes());
        typ.extend(44_u32.to_le_bytes());
        typ.extend([1_u8, 0, 0, 0]);
        typ.extend(1_u32.to_le_bytes());
        typ.extend(28_u32.to_le_bytes());
        typ.extend(4_u32.to_le_bytes());
        typ.extend(0_u32.to_le_bytes()); // first entry at payload start
        typ.extend(8_u16.to_le_bytes());
        typ.extend(0_u16.to_le_bytes());
        typ.extend(0_u32.to_le_bytes()); // key string index
        typ.extend([8, 0, 0, 3]); // Res_value string
        typ.extend(0_u32.to_le_bytes()); // global pool index
        let package_size = 288 + type_pool.len() + key_pool.len() + spec.len() + typ.len();
        let mut package = vec![0_u8; 288];
        package[..2].copy_from_slice(&0x0200_u16.to_le_bytes());
        package[2..4].copy_from_slice(&288_u16.to_le_bytes());
        package[4..8]
            .copy_from_slice(&(u32::try_from(package_size).unwrap_or(u32::MAX)).to_le_bytes());
        package[8..12].copy_from_slice(&0x7f_u32.to_le_bytes());
        package[268..272].copy_from_slice(&288_u32.to_le_bytes());
        package[276..280].copy_from_slice(
            &(u32::try_from(288 + type_pool.len()).unwrap_or(u32::MAX)).to_le_bytes(),
        );
        package.extend(type_pool);
        package.extend(key_pool);
        package.extend(spec);
        package.extend(typ);
        let mut table = Vec::new();
        table.extend(2_u16.to_le_bytes());
        table.extend(12_u16.to_le_bytes());
        table.extend(
            (u32::try_from(12 + global.len() + package.len()).unwrap_or(u32::MAX)).to_le_bytes(),
        );
        table.extend(1_u32.to_le_bytes());
        table.extend(global);
        table.extend(package);
        table
    }

    fn pool_utf16(value: &str) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend(1_u16.to_le_bytes());
        data.extend(28_u16.to_le_bytes());
        data.extend(0_u32.to_le_bytes());
        data.extend(1_u32.to_le_bytes());
        data.extend(0_u32.to_le_bytes());
        data.extend(0_u32.to_le_bytes());
        data.extend(32_u32.to_le_bytes());
        data.extend(0_u32.to_le_bytes());
        data.extend(0_u32.to_le_bytes());
        data.extend(
            u16::try_from(value.encode_utf16().count())
                .unwrap_or(0)
                .to_le_bytes(),
        );
        for unit in value.encode_utf16() {
            data.extend(unit.to_le_bytes());
        }
        data.extend(0_u16.to_le_bytes());
        while data.len() % 4 != 0 {
            data.push(0);
        }
        let length = u32::try_from(data.len()).unwrap_or(0);
        data[4..8].copy_from_slice(&length.to_le_bytes());
        data
    }

    fn utf16_sample(value: &str) -> Vec<u8> {
        let original = sample(value);
        let old_global_len = pool(&[value]).len();
        let global = pool_utf16(value);
        let mut table = original[..12].to_vec();
        table.extend(global);
        table.extend_from_slice(&original[12 + old_global_len..]);
        let length = u32::try_from(table.len()).unwrap_or(0);
        table[4..8].copy_from_slice(&length.to_le_bytes());
        table
    }

    #[test]
    fn o13_arsc_rewrites_class_value_and_preserves_package_ids_and_offsets() {
        let aliases =
            std::collections::BTreeMap::from([("com.test.A".to_owned(), "com.test.Z".to_owned())]);
        for original in [sample("com.test.A"), utf16_sample("com.test.A")] {
            let linked =
                super::rewrite_resource_string_aliases(&original, &aliases).unwrap_or_default();
            let inspected = inspect_resource_table(&linked).unwrap_or_default();
            assert_eq!(inspected, ["com.test.Z", "string", "title"]);
            assert_eq!(original.len(), linked.len());
            let before = super::chunk(&original, 12).map_or(0, |x| x.size);
            let after = super::chunk(&linked, 12).map_or(0, |x| x.size);
            assert_eq!(before, after);
            assert_eq!(&original[12 + before..], &linked[12 + before..]);
            let unchanged = super::rewrite_resource_string_aliases(
                &original,
                &std::collections::BTreeMap::new(),
            )
            .unwrap_or_default();
            assert_eq!(unchanged, original);
        }
    }

    #[test]
    fn o13_arsc_rejects_length_changes_and_unreferenced_class_values() {
        let original = sample("com.test.A");
        let different_length = std::collections::BTreeMap::from([(
            "com.test.A".to_owned(),
            "com.test.Longer".to_owned(),
        )]);
        assert!(super::rewrite_resource_string_aliases(&original, &different_length).is_err());
        let aliases =
            std::collections::BTreeMap::from([("com.test.A".to_owned(), "com.test.Z".to_owned())]);
        let mut non_string = original.clone();
        let at = 12
            + pool(&["com.test.A"]).len()
            + 288
            + pool(&["string"]).len()
            + pool(&["title"]).len()
            + 20
            + 36
            + 3;
        non_string[at] = 0x10; // TYPE_INT_DEC replaces TYPE_STRING in entry value
        assert!(inspect_resource_table(&non_string).is_ok());
        assert!(super::rewrite_resource_string_aliases(&non_string, &aliases).is_err());
        let mut truncated = original.clone();
        truncated.pop();
        assert!(super::rewrite_resource_string_aliases(&truncated, &aliases).is_err());
    }

    #[test]
    fn o13_resource_table_reads_string_bindings_without_rewriting() {
        let bytes = sample("com.test.A");
        let names = inspect_resource_table(&bytes).unwrap_or_default();
        assert_eq!(names, ["com.test.A", "string", "title"]);
        assert_eq!(inspect_resource_table(&bytes).unwrap_or_default(), names);
    }

    #[test]
    fn o13_resource_table_rejects_malformed_structure_and_indices() {
        let valid = sample("com.test.A");
        for end in [0, 3, valid.len() - 1] {
            assert!(inspect_resource_table(&valid[..end]).is_err());
        }
        let mut corrupted = valid.clone();
        corrupted[8..12].copy_from_slice(&2_u32.to_le_bytes());
        assert!(inspect_resource_table(&corrupted).is_err());
        let mut bad_global_string_index = valid.clone();
        let start = 12
            + pool(&["com.test.A"]).len()
            + 288
            + pool(&["string"]).len()
            + pool(&["title"]).len()
            + 20;
        bad_global_string_index[start + 40..start + 44].copy_from_slice(&99_u32.to_le_bytes());
        assert!(inspect_resource_table(&bad_global_string_index).is_err());
        let mut wrong_type_pool_offset = valid.clone();
        let start = 12 + pool(&["com.test.A"]).len();
        wrong_type_pool_offset[start + 268..start + 272].copy_from_slice(&0_u32.to_le_bytes());
        assert!(inspect_resource_table(&wrong_type_pool_offset).is_err());
    }
}
