use crate::container::{open, seal, ContainerKind};
use crate::error::{DataProtectionError, Result};
use crate::key::{hex_lower, KeyDomain, KeySchedule, ITEM_ID_LEN};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const BUNDLE_MAGIC: &[u8; 4] = b"NSRB";
const BUNDLE_VERSION: u8 = 1;
const BUNDLE_HEADER_LEN: usize = 4 + 1 + 3 + 4;
const ENTRY_HEADER_LEN: usize = ITEM_ID_LEN + 8;
const MAX_BUNDLE_ENTRIES: u32 = 100_000;
const DEFAULT_MAX_RESOURCE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceSelector {
    include: Vec<String>,
    exclude: Vec<String>,
    pub max_resource_bytes: u64,
    pub allow_assets: bool,
    pub allow_res_raw: bool,
}

impl Default for ResourceSelector {
    fn default() -> Self {
        Self {
            include: Vec::new(),
            exclude: Vec::new(),
            max_resource_bytes: DEFAULT_MAX_RESOURCE_BYTES,
            allow_assets: true,
            allow_res_raw: true,
        }
    }
}

impl ResourceSelector {
    pub fn include(&mut self, pattern: impl Into<String>) {
        self.include.push(pattern.into());
    }

    pub fn exclude(&mut self, pattern: impl Into<String>) {
        self.exclude.push(pattern.into());
    }

    pub fn evaluate(&self, path: &str, size: u64) -> Result<ResourceDecision> {
        let normalized = normalize_resource_path(path)?;

        if size > self.max_resource_bytes {
            return Ok(ResourceDecision {
                path: normalized,
                protect: false,
                reason: "resource exceeds configured size budget".into(),
            });
        }

        if is_never_encrypt_path(&normalized) {
            return Ok(ResourceDecision {
                path: normalized,
                protect: false,
                reason: "Android/runtime contract resource".into(),
            });
        }

        if self
            .exclude
            .iter()
            .any(|pattern| glob_match(pattern, &normalized))
        {
            return Ok(ResourceDecision {
                path: normalized,
                protect: false,
                reason: "explicit exclusion".into(),
            });
        }

        if self
            .include
            .iter()
            .any(|pattern| glob_match(pattern, &normalized))
        {
            return Ok(ResourceDecision {
                path: normalized,
                protect: true,
                reason: "explicit inclusion".into(),
            });
        }

        let default_allowed = (self.allow_assets && normalized.starts_with("assets/"))
            || (self.allow_res_raw && normalized.starts_with("res/raw/"));

        Ok(ResourceDecision {
            path: normalized,
            protect: default_allowed,
            reason: if default_allowed {
                "safe default resource surface".into()
            } else {
                "resource is outside safe default surfaces".into()
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceDecision {
    pub path: String,
    pub protect: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceInput {
    pub path: String,
    pub bytes: Vec<u8>,
}

impl ResourceInput {
    #[must_use]
    pub fn new(path: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResourceRecord {
    pub path: String,
    pub opaque_id: String,
    pub original_bytes: u64,
    pub protected_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceBundleBuild {
    pub bytes: Vec<u8>,
    pub records: Vec<ProtectedResourceRecord>,
    pub skipped: Vec<ResourceDecision>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BundleEntry {
    item_id: [u8; ITEM_ID_LEN],
    container: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceBundle {
    entries: BTreeMap<[u8; ITEM_ID_LEN], Vec<u8>>,
}

impl ResourceBundle {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BUNDLE_HEADER_LEN {
            return Err(DataProtectionError::InvalidBundle(
                "truncated resource bundle header".into(),
            ));
        }
        if &bytes[..4] != BUNDLE_MAGIC {
            return Err(DataProtectionError::InvalidBundle(
                "invalid resource bundle magic".into(),
            ));
        }
        if bytes[4] != BUNDLE_VERSION {
            return Err(DataProtectionError::UnsupportedVersion(bytes[4]));
        }
        if bytes[5..8] != [0, 0, 0] {
            return Err(DataProtectionError::InvalidBundle(
                "reserved bundle header bytes are non-zero".into(),
            ));
        }

        let count = read_u32(bytes, 8)?;
        if count > MAX_BUNDLE_ENTRIES {
            return Err(DataProtectionError::InvalidBundle(format!(
                "bundle entry count {count} exceeds {MAX_BUNDLE_ENTRIES}"
            )));
        }

        let mut cursor = BUNDLE_HEADER_LEN;
        let mut entries = BTreeMap::new();
        for _ in 0..count {
            let end_header = cursor.checked_add(ENTRY_HEADER_LEN).ok_or_else(|| {
                DataProtectionError::InvalidBundle("entry header overflow".into())
            })?;
            if end_header > bytes.len() {
                return Err(DataProtectionError::InvalidBundle(
                    "truncated bundle entry header".into(),
                ));
            }

            let mut item_id = [0_u8; ITEM_ID_LEN];
            item_id.copy_from_slice(&bytes[cursor..cursor + ITEM_ID_LEN]);
            let container_len = read_u64(bytes, cursor + ITEM_ID_LEN)?;
            let container_len = usize::try_from(container_len).map_err(|_| {
                DataProtectionError::InvalidBundle(
                    "entry container length does not fit usize".into(),
                )
            })?;
            cursor = end_header;
            let end = cursor
                .checked_add(container_len)
                .ok_or_else(|| DataProtectionError::InvalidBundle("entry size overflow".into()))?;
            let container = bytes
                .get(cursor..end)
                .ok_or_else(|| DataProtectionError::InvalidBundle("truncated bundle entry".into()))?
                .to_vec();

            if entries.insert(item_id, container).is_some() {
                return Err(DataProtectionError::InvalidBundle(
                    "duplicate opaque resource identifier".into(),
                ));
            }
            cursor = end;
        }

        if cursor != bytes.len() {
            return Err(DataProtectionError::InvalidBundle(
                "trailing bytes after final resource entry".into(),
            ));
        }

        Ok(Self { entries })
    }

    pub fn decrypt(&self, schedule: &KeySchedule, path: &str) -> Result<Vec<u8>> {
        let normalized = normalize_resource_path(path)?;
        let logical_id = resource_logical_id(&normalized);
        let item_id = schedule.opaque_item_id(KeyDomain::Resource, &logical_id)?;
        let container = self
            .entries
            .get(&item_id)
            .ok_or(DataProtectionError::IdentifierMismatch)?;
        open(schedule, ContainerKind::Resource, &logical_id, container)
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn contains_opaque_id(&self, item_id: &[u8; ITEM_ID_LEN]) -> bool {
        self.entries.contains_key(item_id)
    }
}

pub fn build_resource_bundle(
    schedule: &KeySchedule,
    selector: &ResourceSelector,
    inputs: &[ResourceInput],
) -> Result<ResourceBundleBuild> {
    let mut seen_paths = BTreeSet::new();
    let mut entries = Vec::new();
    let mut records = Vec::new();
    let mut skipped = Vec::new();

    for input in inputs {
        let size = u64::try_from(input.bytes.len()).map_err(|_| {
            DataProtectionError::ResourceRejected("resource length does not fit u64".into())
        })?;
        let decision = selector.evaluate(&input.path, size)?;
        if !decision.protect {
            skipped.push(decision);
            continue;
        }

        if !seen_paths.insert(decision.path.clone()) {
            return Err(DataProtectionError::DuplicateIdentifier(decision.path));
        }

        let logical_id = resource_logical_id(&decision.path);
        let item_id = schedule.opaque_item_id(KeyDomain::Resource, &logical_id)?;
        let container = seal(schedule, ContainerKind::Resource, &logical_id, &input.bytes)?;

        records.push(ProtectedResourceRecord {
            path: decision.path,
            opaque_id: hex_lower(&item_id),
            original_bytes: size,
            protected_bytes: u64::try_from(container.len()).map_err(|_| {
                DataProtectionError::InvalidBundle(
                    "protected resource length does not fit u64".into(),
                )
            })?,
        });
        entries.push(BundleEntry { item_id, container });
    }

    entries.sort_by_key(|entry| entry.item_id);
    let bytes = serialize_bundle(&entries)?;

    Ok(ResourceBundleBuild {
        bytes,
        records,
        skipped,
    })
}

pub fn normalize_resource_path(path: &str) -> Result<String> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.as_bytes().contains(&0)
    {
        return Err(DataProtectionError::InvalidResourcePath(path.into()));
    }

    let mut parts = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(DataProtectionError::InvalidResourcePath(path.into()));
        }
        parts.push(part);
    }
    Ok(parts.join("/"))
}

fn serialize_bundle(entries: &[BundleEntry]) -> Result<Vec<u8>> {
    let count = u32::try_from(entries.len())
        .map_err(|_| DataProtectionError::InvalidBundle("too many resource entries".into()))?;
    if count > MAX_BUNDLE_ENTRIES {
        return Err(DataProtectionError::InvalidBundle(format!(
            "bundle entry count {count} exceeds {MAX_BUNDLE_ENTRIES}"
        )));
    }

    let mut output = Vec::new();
    output.extend_from_slice(BUNDLE_MAGIC);
    output.push(BUNDLE_VERSION);
    output.extend_from_slice(&[0, 0, 0]);
    output.extend_from_slice(&count.to_le_bytes());

    for entry in entries {
        output.extend_from_slice(&entry.item_id);
        let length = u64::try_from(entry.container.len()).map_err(|_| {
            DataProtectionError::InvalidBundle("container length does not fit u64".into())
        })?;
        output.extend_from_slice(&length.to_le_bytes());
        output.extend_from_slice(&entry.container);
    }

    Ok(output)
}

fn resource_logical_id(path: &str) -> String {
    format!("resource:{path}")
}

fn is_never_encrypt_path(path: &str) -> bool {
    path == "AndroidManifest.xml"
        || path == "resources.arsc"
        || path.starts_with("classes") && path.ends_with(".dex")
        || path.starts_with("lib/")
        || path.starts_with("META-INF/")
        || path.starts_with("res/layout/")
        || path.starts_with("res/xml/")
        || path.starts_with("res/drawable/")
        || path.starts_with("res/mipmap/")
        || path.starts_with("res/values/")
}

fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;

    for token in pattern {
        let mut current = vec![false; value.len() + 1];
        if *token == b'*' {
            current[0] = previous[0];
            for index in 1..=value.len() {
                current[index] = previous[index] || current[index - 1];
            }
        } else {
            for index in 1..=value.len() {
                current[index] =
                    previous[index - 1] && (*token == b'?' || *token == value[index - 1]);
            }
        }
        previous = current;
    }

    previous[value.len()]
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| DataProtectionError::InvalidBundle("truncated u32".into()))?;
    let mut array = [0_u8; 4];
    array.copy_from_slice(slice);
    Ok(u32::from_le_bytes(array))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let slice = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| DataProtectionError::InvalidBundle("truncated u64".into()))?;
    let mut array = [0_u8; 8];
    array.copy_from_slice(slice);
    Ok(u64::from_le_bytes(array))
}

#[cfg(test)]
mod tests {
    use super::{glob_match, normalize_resource_path};

    #[test]
    fn glob_is_deterministic() {
        assert!(glob_match("assets/*.json", "assets/config.json"));
        assert!(glob_match("res/raw/?ata.bin", "res/raw/data.bin"));
        assert!(!glob_match("assets/*.json", "res/raw/config.json"));
    }

    #[test]
    fn path_normalizer_rejects_traversal() {
        assert!(normalize_resource_path("assets/../secret").is_err());
        assert!(normalize_resource_path("/absolute").is_err());
        assert_eq!(
            normalize_resource_path("assets/config.json").expect("valid path"),
            "assets/config.json"
        );
    }
}
