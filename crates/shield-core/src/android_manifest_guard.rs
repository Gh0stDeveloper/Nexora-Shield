//! Append a private startup provider without re-linking existing Android contracts.
use super::{
    chunk, inspect_binary_xml, reject, u16_at, u32_at, u8_at, usize32, Result, ELEMENT_END,
    ELEMENT_START, MAX_POOL_STRINGS, RESOURCE_MAP, STRING_POOL, TYPE_STRING,
};

const PROVIDER: &str = "dev.nexora.shield.NexoraProvider";
const ANDROID: &str = "http://schemas.android.com/apk/res/android";

pub(crate) fn inject_guard_provider(bytes: &[u8], authority: &str) -> Result<Vec<u8>> {
    let mut strings = inspect_binary_xml(bytes)?;
    if strings.iter().any(|s| s == PROVIDER || s == authority) {
        return Err(reject("guard provider namespace collision"));
    }
    let original_count = strings.len();
    let mut chunks = Vec::new();
    let mut offset = 8;
    let mut map = Vec::new();
    while offset < bytes.len() {
        let item = chunk(bytes, offset)?;
        if item.kind == RESOURCE_MAP {
            if !map.is_empty() {
                return Err(reject("multiple resource maps"));
            }
            map = (offset + 8..offset + item.size)
                .step_by(4)
                .map(|at| u32_at(bytes, at))
                .collect::<Result<Vec<_>>>()?;
        }
        if item.kind == STRING_POOL && (u32_at(bytes, offset + 12)? != 0 || item.header != 28) {
            return Err(reject("styled/extended manifest pool unsupported"));
        }
        chunks.push((offset, item));
        offset += item.size;
    }
    if map.len() > original_count {
        return Err(reject("oversized resource map"));
    }
    map.resize(original_count, 0);
    let tag = append(&mut strings, "provider")?;
    let namespace = if let Some(index) = strings.iter().position(|value| value == ANDROID) {
        u32::try_from(index).map_err(|_| reject("namespace index overflow"))?
    } else {
        append(&mut strings, ANDROID)?
    };
    let class = append(&mut strings, PROVIDER)?;
    let authority = append(&mut strings, authority)?;
    // New attribute-name slots prevent changing any existing resource-map binding.
    let attrs = [
        ("name", 0x0101_0003, TYPE_STRING, class),
        ("exported", 0x0101_0010, 0x12, 0),
        ("authorities", 0x0101_0018, TYPE_STRING, authority),
        ("initOrder", 0x0101_001a, 0x10, 0x7fff_ffff),
    ];
    let mut attributes = Vec::new();
    for (name, id, kind, value) in attrs {
        let index = append(&mut strings, name)?;
        map.resize(strings.len(), 0);
        map[index as usize] = id;
        attributes.push((index, kind, value));
    }
    let provider = provider_node(tag, namespace, &attributes)?;
    let mut output = bytes[..8].to_vec();
    output.extend(encode_pool(&strings)?);
    output.extend(encode_map(&map)?);
    let mut stack = Vec::new();
    let mut applications = 0;
    let mut inserted = 0;
    for (at, item) in chunks {
        if matches!(item.kind, STRING_POOL | RESOURCE_MAP) {
            continue;
        }
        if item.kind == ELEMENT_START {
            let name = &strings[usize32(bytes, at + 20)?];
            if name == "application" && stack.len() == 1 {
                applications += 1;
            }
            audit_process_contract(bytes, at, &strings)?;
            stack.push(name.as_str());
        } else if item.kind == ELEMENT_END {
            let name = &strings[usize32(bytes, at + 20)?];
            if stack.pop() != Some(name.as_str()) {
                return Err(reject("manifest hierarchy mismatch"));
            }
            if name == "application" && stack.len() == 1 {
                output.extend_from_slice(&provider);
                inserted += 1;
            }
        }
        output.extend_from_slice(&bytes[at..at + item.size]);
    }
    if applications != 1 || inserted != 1 || !stack.is_empty() {
        return Err(reject("ambiguous application element"));
    }
    let size = u32::try_from(output.len()).map_err(|_| reject("manifest size overflow"))?;
    output[4..8].copy_from_slice(&size.to_le_bytes());
    let result = inspect_binary_xml(&output)?;
    if result[..original_count] != strings[..original_count] {
        return Err(reject("manifest string identity changed"));
    }
    Ok(output)
}

fn audit_process_contract(bytes: &[u8], at: usize, strings: &[String]) -> Result<()> {
    let tag = &strings[usize32(bytes, at + 20)?];
    if tag == "instrumentation" {
        return Err(reject(
            "instrumentation startup requires a verified early-entry binder",
        ));
    }
    let first = at + 16 + usize::from(u16_at(bytes, at + 24)?);
    for n in 0..usize::from(u16_at(bytes, at + 28)?) {
        let attr = first + n * 20;
        let ns = u32_at(bytes, attr)?;
        if ns == u32::MAX || strings.get(ns as usize).map(String::as_str) != Some(ANDROID) {
            continue;
        }
        let name = &strings[usize32(bytes, attr + 4)?];
        if tag == "application"
            && matches!(
                name.as_str(),
                "name" | "appComponentFactory" | "backupAgent"
            )
        {
            return Err(reject(
                "custom Application/factory/backup startup requires an early-entry binder",
            ));
        }
        if tag == "provider"
            && name == "initOrder"
            && (!matches!(u8_at(bytes, attr + 15)?, 0x10 | 0x11)
                || u32_at(bytes, attr + 16)? == 0x7fff_ffff)
        {
            return Err(reject(
                "existing provider initialization order is ambiguous",
            ));
        }
        if name == "process" || (name == "directBootAware" && u32_at(bytes, attr + 16)? != 0) {
            return Err(reject(
                "guard startup requires a single default unlocked process",
            ));
        }
    }
    Ok(())
}

pub(crate) fn runtime_manifest_version(bytes: &[u8]) -> Result<u64> {
    let strings = inspect_binary_xml(bytes)?;
    let mut offset = 8;
    let mut low = 0;
    let mut high = 0;
    let mut seen = std::collections::BTreeSet::new();
    while offset < bytes.len() {
        let item = chunk(bytes, offset)?;
        if item.kind == ELEMENT_START && strings[usize32(bytes, offset + 20)?] == "manifest" {
            let first = offset + 16 + usize::from(u16_at(bytes, offset + 24)?);
            for n in 0..usize::from(u16_at(bytes, offset + 28)?) {
                let at = first + n * 20;
                let ns = u32_at(bytes, at)?;
                let name = &strings[usize32(bytes, at + 4)?];
                if ns != u32::MAX
                    && strings[ns as usize] == ANDROID
                    && matches!(name.as_str(), "versionCode" | "versionCodeMajor")
                {
                    if !seen.insert(name) || !matches!(u8_at(bytes, at + 15)?, 0x10 | 0x11) {
                        return Err(reject("ambiguous version code"));
                    }
                    if name == "versionCode" {
                        low = u32_at(bytes, at + 16)?;
                    } else {
                        high = u32_at(bytes, at + 16)?;
                    }
                }
            }
        }
        offset += item.size;
    }
    Ok((u64::from(high) << 32) | u64::from(low))
}

fn append(strings: &mut Vec<String>, value: &str) -> Result<u32> {
    if strings.len() >= MAX_POOL_STRINGS {
        return Err(reject("manifest string budget exceeded"));
    }
    let index = u32::try_from(strings.len()).map_err(|_| reject("string index overflow"))?;
    strings.push(value.to_owned());
    Ok(index)
}
fn encode_pool(strings: &[String]) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for string in strings {
        offsets.push(u32::try_from(data.len()).map_err(|_| reject("pool size overflow"))?);
        let units = string.encode_utf16().collect::<Vec<_>>();
        let length = u32::try_from(units.len()).map_err(|_| reject("string overflow"))?;
        if length > 0x7fff {
            data.extend(
                u16::try_from((length >> 16) | 0x8000)
                    .map_err(|_| reject("string overflow"))?
                    .to_le_bytes(),
            );
        }
        data.extend(
            u16::try_from(length & 0xffff)
                .map_err(|_| reject("string overflow"))?
                .to_le_bytes(),
        );
        for unit in units {
            data.extend(unit.to_le_bytes());
        }
        data.extend([0, 0]);
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let start = u32::try_from(28 + strings.len() * 4).map_err(|_| reject("pool overflow"))?;
    let mut out = Vec::new();
    out.extend(STRING_POOL.to_le_bytes());
    out.extend(28u16.to_le_bytes());
    out.extend(
        (start + u32::try_from(data.len()).map_err(|_| reject("pool overflow"))?).to_le_bytes(),
    );
    out.extend(
        u32::try_from(strings.len())
            .map_err(|_| reject("pool overflow"))?
            .to_le_bytes(),
    );
    out.extend(0u32.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(start.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    for value in offsets {
        out.extend(value.to_le_bytes());
    }
    out.extend(data);
    Ok(out)
}
fn encode_map(map: &[u32]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend(RESOURCE_MAP.to_le_bytes());
    out.extend(8u16.to_le_bytes());
    out.extend(
        u32::try_from(8 + map.len() * 4)
            .map_err(|_| reject("resource map overflow"))?
            .to_le_bytes(),
    );
    for value in map {
        out.extend(value.to_le_bytes());
    }
    Ok(out)
}
fn provider_node(tag: u32, namespace: u32, attrs: &[(u32, u8, u32)]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend(ELEMENT_START.to_le_bytes());
    out.extend(16u16.to_le_bytes());
    out.extend(
        u32::try_from(36 + attrs.len() * 20)
            .map_err(|_| reject("provider size overflow"))?
            .to_le_bytes(),
    );
    for value in [0, u32::MAX, u32::MAX, tag] {
        out.extend(value.to_le_bytes());
    }
    for value in [
        20,
        20,
        u16::try_from(attrs.len()).map_err(|_| reject("attribute count overflow"))?,
        0,
        0,
        0,
    ] {
        out.extend(value.to_le_bytes());
    }
    for (name, kind, value) in attrs {
        for item in [
            namespace,
            *name,
            if *kind == TYPE_STRING {
                *value
            } else {
                u32::MAX
            },
        ] {
            out.extend(item.to_le_bytes());
        }
        out.extend(8u16.to_le_bytes());
        out.push(0);
        out.push(*kind);
        out.extend(value.to_le_bytes());
    }
    out.extend(ELEMENT_END.to_le_bytes());
    out.extend(16u16.to_le_bytes());
    out.extend(24u32.to_le_bytes());
    for value in [0, u32::MAX, u32::MAX, tag] {
        out.extend(value.to_le_bytes());
    }
    Ok(out)
}
