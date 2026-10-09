//! Strict, bounded Android ResXMLTree reader for O.1.3 name-link auditing.
//! This does NOT patch compiled XML, string offsets or resource references.
//! A malformed or unknown chunk fails closed rather than being treated as text.
use crate::{CoreError, Result};

const XML_TREE: u16 = 0x0003;
const STRING_POOL: u16 = 0x0001;
const RESOURCE_MAP: u16 = 0x0180;
const NS_START: u16 = 0x0100;
const NS_END: u16 = 0x0101;
const ELEMENT_START: u16 = 0x0102;
const ELEMENT_END: u16 = 0x0103;
const CDATA: u16 = 0x0104;
const TYPE_STRING: u8 = 0x03;
const UTF8_FLAG: u32 = 0x100;
const MAX_POOL_STRINGS: usize = 200_000;
const MAX_STRING_UNITS: usize = 1_048_576;

fn reject(reason: &str) -> CoreError {
    CoreError::InvalidRequest(format!("O.1.3 Android binary XML: {reason}"))
}

fn slice(data: &[u8], start: usize, count: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(count)
        .ok_or_else(|| reject("offset overflow"))?;
    data.get(start..end)
        .ok_or_else(|| reject("truncated structure or invalid offset"))
}

fn u8_at(data: &[u8], at: usize) -> Result<u8> {
    Ok(*slice(data, at, 1)?
        .first()
        .ok_or_else(|| reject("truncated byte"))?)
}

fn u16_at(data: &[u8], at: usize) -> Result<u16> {
    let b = slice(data, at, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    let b = slice(data, at, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn usize32(data: &[u8], at: usize) -> Result<usize> {
    usize::try_from(u32_at(data, at)?).map_err(|_| reject("integer overflow"))
}

#[derive(Debug, Clone, Copy)]
struct Chunk {
    kind: u16,
    header: usize,
    size: usize,
}

fn chunk(data: &[u8], at: usize) -> Result<Chunk> {
    let kind = u16_at(data, at)?;
    let header = usize::from(u16_at(data, at + 2)?);
    let size = usize32(data, at + 4)?;
    if header < 8 || size < header {
        return Err(reject("invalid chunk header/size"));
    }
    let _ = slice(data, at, size)?;
    Ok(Chunk { kind, header, size })
}

fn utf8_length(data: &[u8], at: &mut usize) -> Result<usize> {
    let first = u8_at(data, *at)?;
    *at = at.checked_add(1).ok_or_else(|| reject("length overflow"))?;
    if first & 0x80 == 0 {
        return Ok(usize::from(first));
    }
    let next = u8_at(data, *at)?;
    *at = at.checked_add(1).ok_or_else(|| reject("length overflow"))?;
    Ok((usize::from(first & 0x7f) << 8) | usize::from(next))
}

fn utf16_length(data: &[u8], at: &mut usize) -> Result<usize> {
    let first = u16_at(data, *at)?;
    *at = at.checked_add(2).ok_or_else(|| reject("length overflow"))?;
    if first & 0x8000 == 0 {
        return Ok(usize::from(first));
    }
    let next = u16_at(data, *at)?;
    *at = at.checked_add(2).ok_or_else(|| reject("length overflow"))?;
    Ok((usize::from(first & 0x7fff) << 16) | usize::from(next))
}

fn decode_pool_string(bytes: &[u8], at: usize, utf8: bool) -> Result<String> {
    let mut cursor = at;
    if utf8 {
        let utf16_units = utf8_length(bytes, &mut cursor)?;
        let length = utf8_length(bytes, &mut cursor)?;
        if length > MAX_STRING_UNITS || utf16_units > MAX_STRING_UNITS {
            return Err(reject("string exceeds character budget"));
        }
        let text = std::str::from_utf8(slice(bytes, cursor, length)?)
            .map_err(|_| reject("invalid UTF-8 string pool entry"))?;
        cursor = cursor
            .checked_add(length)
            .ok_or_else(|| reject("length overflow"))?;
        if u8_at(bytes, cursor)? != 0 || text.encode_utf16().count() != utf16_units {
            return Err(reject(
                "UTF-8 entry has invalid terminator or UTF-16 length",
            ));
        }
        return Ok(text.to_owned());
    }
    let length = utf16_length(bytes, &mut cursor)?;
    if length > MAX_STRING_UNITS {
        return Err(reject("string exceeds UTF-16 character budget"));
    }
    let units_bytes = length
        .checked_mul(2)
        .ok_or_else(|| reject("length overflow"))?;
    let raw = slice(bytes, cursor, units_bytes)?;
    let units = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    cursor = cursor
        .checked_add(units_bytes)
        .ok_or_else(|| reject("length overflow"))?;
    if u16_at(bytes, cursor)? != 0 {
        return Err(reject("invalid UTF-16 terminator"));
    }
    String::from_utf16(&units).map_err(|_| reject("unpaired UTF-16 surrogate"))
}

fn parse_pool(data: &[u8], at: usize, item: Chunk) -> Result<Vec<String>> {
    if item.header < 28 {
        return Err(reject("string pool header too small"));
    }
    let count = usize32(data, at + 8)?;
    let styles = usize32(data, at + 12)?;
    let flags = u32_at(data, at + 16)?;
    let strings_start = usize32(data, at + 20)?;
    let styles_start = usize32(data, at + 24)?;
    if count > MAX_POOL_STRINGS || styles > MAX_POOL_STRINGS {
        return Err(reject("string/style count exceeds budget"));
    }
    let slots = count
        .checked_add(styles)
        .and_then(|sum| sum.checked_mul(4))
        .ok_or_else(|| reject("pool index overflow"))?;
    let slot_end = item
        .header
        .checked_add(slots)
        .ok_or_else(|| reject("pool overflow"))?;
    if slot_end > item.size
        || strings_start < slot_end
        || strings_start >= item.size
        || (styles > 0 && (styles_start < strings_start || styles_start >= item.size))
        || (styles == 0 && styles_start != 0)
    {
        return Err(reject("invalid string/style table offsets"));
    }
    let end = if styles_start > 0 {
        styles_start
    } else {
        item.size
    };
    let payload = slice(data, at, item.size)?;
    let strings_data = slice(payload, strings_start, end - strings_start)?;
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        let pos = at
            .checked_add(item.header)
            .and_then(|x| x.checked_add(index * 4))
            .ok_or_else(|| reject("string index overflow"))?;
        let offset = usize32(data, pos)?;
        if offset >= strings_data.len() {
            return Err(reject("string offset outside pool payload"));
        }
        result.push(decode_pool_string(
            strings_data,
            offset,
            flags & UTF8_FLAG != 0,
        )?);
    }
    // Styles are not rewritten here. Validate that every declared style
    // offset remains within the bounds of the chunk.
    if styles > 0 {
        let style_payload = slice(payload, styles_start, item.size - styles_start)?;
        for index in 0..styles {
            let pos = at
                .checked_add(item.header + count * 4)
                .and_then(|x| x.checked_add(index * 4))
                .ok_or_else(|| reject("style offset overflow"))?;
            let offset = usize32(data, pos)?;
            if offset >= style_payload.len() {
                return Err(reject("style span outside chunk"));
            }
        }
    }
    Ok(result)
}

fn string_index(data: &[u8], at: usize, count: usize, nullable: bool) -> Result<()> {
    let index = u32_at(data, at)?;
    if nullable && index == u32::MAX {
        return Ok(());
    }
    if usize::try_from(index).map_or(true, |i| i >= count) {
        return Err(reject("XML node string reference outside string pool"));
    }
    Ok(())
}

fn typed_value(data: &[u8], at: usize, count: usize) -> Result<()> {
    if u16_at(data, at)? != 8 || u8_at(data, at + 2)? != 0 {
        return Err(reject("invalid typed-value header"));
    }
    if u8_at(data, at + 3)? == TYPE_STRING {
        string_index(data, at + 4, count, false)?;
    }
    Ok(())
}

fn validate_node(data: &[u8], at: usize, item: Chunk, count: usize) -> Result<()> {
    if item.header != 16 || item.size < 24 {
        return Err(reject("invalid XML tree node header"));
    }
    string_index(data, at + 12, count, true)?; // optional comment index
    match item.kind {
        NS_START | NS_END | ELEMENT_END => {
            string_index(data, at + 16, count, true)?;
            string_index(data, at + 20, count, item.kind != ELEMENT_END)?;
        }
        ELEMENT_START => {
            if item.size < 36 {
                return Err(reject("start element smaller than attribute extension"));
            }
            string_index(data, at + 16, count, true)?;
            string_index(data, at + 20, count, false)?;
            let attr_start = usize::from(u16_at(data, at + 24)?);
            let attr_size = usize::from(u16_at(data, at + 26)?);
            let attr_count = usize::from(u16_at(data, at + 28)?);
            if attr_start < 20 || attr_size != 20 {
                return Err(reject("invalid attribute offset/stride"));
            }
            for special in [at + 30, at + 32, at + 34] {
                if usize::from(u16_at(data, special)?) > attr_count {
                    return Err(reject("attribute special index outside list"));
                }
            }
            let attrs = 16_usize
                .checked_add(attr_start)
                .ok_or_else(|| reject("attribute start overflow"))?;
            let count_bytes = attr_count
                .checked_mul(attr_size)
                .ok_or_else(|| reject("attribute count overflow"))?;
            if attrs
                .checked_add(count_bytes)
                .ok_or_else(|| reject("attribute bounds overflow"))?
                > item.size
            {
                return Err(reject("attribute list outside XML node"));
            }
            for n in 0..attr_count {
                let base = at + attrs + n * attr_size;
                string_index(data, base, count, true)?;
                string_index(data, base + 4, count, false)?;
                string_index(data, base + 8, count, true)?;
                typed_value(data, base + 12, count)?;
            }
        }
        CDATA => {
            if item.size < 28 {
                return Err(reject("truncated CDATA"));
            }
            string_index(data, at + 16, count, true)?;
            typed_value(data, at + 20, count)?;
        }
        _ => return Err(reject("unknown XML tree node type")),
    }
    Ok(())
}

/// Read all structurally valid string-pool entries from compiled Android XML.
/// Returning strings is NOT authorization to rewrite or sign the APK.
/// Unrecognized node layouts, invalid lengths and unknown chunks are refused.
///
/// # Errors
///
/// Fails on malformed XML, unknown chunks, unbounded pools and bad references.
pub(crate) fn inspect_binary_xml(bytes: &[u8]) -> Result<Vec<String>> {
    let root = chunk(bytes, 0)?;
    if root.kind != XML_TREE || root.header != 8 || root.size != bytes.len() {
        return Err(reject("invalid XML root chunk"));
    }
    let mut offset = root.header;
    let mut strings = None;
    let mut saw_start = false;
    let mut depth = 0_usize;
    let mut closed = false;
    while offset < bytes.len() {
        let item = chunk(bytes, offset)?;
        if strings.is_none() {
            if item.kind != STRING_POOL {
                return Err(reject("XML must begin with a string pool"));
            }
            strings = Some(parse_pool(bytes, offset, item)?);
        } else if item.kind == RESOURCE_MAP {
            if item.header != 8 || (item.size - item.header) % 4 != 0 || saw_start {
                return Err(reject("invalid resource map layout/order"));
            }
        } else {
            let count = strings.as_ref().map_or(0, Vec::len);
            validate_node(bytes, offset, item, count)?;
            match item.kind {
                ELEMENT_START => {
                    if closed {
                        return Err(reject("multiple XML document roots"));
                    }
                    depth = depth
                        .checked_add(1)
                        .ok_or_else(|| reject("node depth overflow"))?;
                    if depth > 256 {
                        return Err(reject("XML node depth limit exceeded"));
                    }
                    saw_start = true;
                }
                ELEMENT_END => {
                    if depth == 0 {
                        return Err(reject("unbalanced end element"));
                    }
                    depth -= 1;
                    if depth == 0 {
                        closed = true;
                    }
                }
                CDATA if depth == 0 => return Err(reject("CDATA outside document root")),
                _ => {}
            }
        }
        offset = offset
            .checked_add(item.size)
            .ok_or_else(|| reject("chunk offset overflow"))?;
    }
    if !saw_start || !closed || depth != 0 {
        return Err(reject("XML document root is missing or unbalanced"));
    }
    strings.ok_or_else(|| reject("missing string pool"))
}

#[cfg(test)]
mod tests {
    use super::inspect_binary_xml;

    fn le16(n: u16) -> [u8; 2] {
        n.to_le_bytes()
    }
    fn le32(n: u32) -> [u8; 4] {
        n.to_le_bytes()
    }

    fn chunk(kind: u16, header: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(le16(kind));
        out.extend(le16(header));
        out.extend(le32(u32::try_from(payload.len() + 8).unwrap_or(u32::MAX)));
        out.extend(payload);
        out
    }

    fn sample(utf8: bool, string: &str) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend(le32(1));
        data.extend(le32(0));
        data.extend(le32(if utf8 { 0x100 } else { 0 }));
        data.extend(le32(32));
        data.extend(le32(0));
        data.extend(le32(0));
        if utf8 {
            data.push(u8::try_from(string.encode_utf16().count()).unwrap_or(0));
            data.push(u8::try_from(string.len()).unwrap_or(0));
            data.extend(string.as_bytes());
            data.push(0);
        } else {
            data.extend(le16(
                u16::try_from(string.encode_utf16().count()).unwrap_or(0),
            ));
            for unit in string.encode_utf16() {
                data.extend(le16(unit));
            }
            data.extend(le16(0));
        }
        let pool = chunk(1, 28, &data);
        let mut open = Vec::new();
        open.extend(le32(1));
        open.extend(le32(u32::MAX));
        open.extend(le32(u32::MAX));
        open.extend(le32(0));
        open.extend(le16(20));
        open.extend(le16(20));
        open.extend(le16(0));
        open.extend(le16(0));
        open.extend(le16(0));
        open.extend(le16(0));
        let start = chunk(0x0102, 16, &open);
        let mut close = Vec::new();
        close.extend(le32(2));
        close.extend(le32(u32::MAX));
        close.extend(le32(u32::MAX));
        close.extend(le32(0));
        let end = chunk(0x0103, 16, &close);
        let mut root = Vec::new();
        root.extend(le16(3));
        root.extend(le16(8));
        root.extend(le32(
            u32::try_from(8 + pool.len() + start.len() + end.len()).unwrap_or(u32::MAX),
        ));
        root.extend(pool);
        root.extend(start);
        root.extend(end);
        root
    }

    #[test]
    fn o13_compiled_xml_accepts_valid_utf8_and_utf16_pools() {
        for utf8 in [true, false] {
            let source = sample(utf8, "manifest");
            let pool = inspect_binary_xml(&source);
            assert_eq!(pool.as_deref(), Ok(["manifest"].as_slice()));
        }
    }

    #[test]
    fn o13_compiled_xml_rejects_truncation_offsets_and_bad_references() {
        for utf8 in [true, false] {
            let valid = sample(utf8, "manifest");
            for length in [0, 1, 3, 7, valid.len() - 1] {
                assert!(inspect_binary_xml(&valid[..length]).is_err());
            }
            let mut wrong_root_size = valid.clone();
            wrong_root_size[4] = 0;
            assert!(inspect_binary_xml(&wrong_root_size).is_err());
            let mut bad_string_idx = valid.clone();
            let pool = 8 + usize::try_from(u32::from_le_bytes(
                valid[12..16].try_into().unwrap_or([0; 4]),
            ))
            .unwrap_or(0);
            bad_string_idx[pool + 20..pool + 24].copy_from_slice(&1_u32.to_le_bytes());
            assert!(inspect_binary_xml(&bad_string_idx).is_err());
            let mut trailing = valid.clone();
            trailing.push(0);
            assert!(inspect_binary_xml(&trailing).is_err());
        }
    }
}
