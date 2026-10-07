use crate::error::{PackageError, Result};
use crate::hash::sha256_file;
use crate::zip::read_zip_directory;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const BUNDLE_CONFIG: &str = "BundleConfig.pb";
const BASE_MANIFEST: &str = "base/manifest/AndroidManifest.xml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleDexInspection {
    pub name: String,
    pub index: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub crc32: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleModuleInspection {
    pub name: String,
    pub manifest_present: bool,
    pub dex_files: Vec<BundleDexInspection>,
    pub dex_sequence_contiguous: bool,
    pub resources_table_present: bool,
    pub resource_entries: usize,
    pub asset_entries: usize,
    pub native_abis: BTreeSet<String>,
    pub baseline_profile_present: bool,
    pub baseline_profile_metadata_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AabInspection {
    pub file_size: u64,
    pub sha256: String,
    pub entry_count: usize,
    pub bundle_config_present: bool,
    pub modules: Vec<BundleModuleInspection>,
    pub dynamic_features: Vec<String>,
    pub bundle_metadata_entries: usize,
}

pub fn inspect_aab(path: &Path) -> Result<AabInspection> {
    let directory = read_zip_directory(path)?;
    let names = directory
        .entries
        .iter()
        .map(|entry| entry.name.as_str())
        .collect::<BTreeSet<_>>();

    let mut module_names = BTreeSet::new();
    for name in &names {
        if let Some(module) = module_from_manifest(name) {
            module_names.insert(module.to_owned());
        }
    }

    let mut modules = Vec::with_capacity(module_names.len());
    for module_name in module_names {
        let prefix = format!("{module_name}/");
        let manifest_name = format!("{module_name}/manifest/AndroidManifest.xml");
        let resources_name = format!("{module_name}/resources.pb");

        let mut dex_files = directory
            .entries
            .iter()
            .filter_map(|entry| {
                let relative = entry.name.strip_prefix(&prefix)?;
                let dex_name = relative.strip_prefix("dex/")?;
                let index = dex_index(dex_name)?;
                Some(BundleDexInspection {
                    name: entry.name.clone(),
                    index,
                    compressed_size: entry.compressed_size,
                    uncompressed_size: entry.uncompressed_size,
                    crc32: entry.crc32,
                })
            })
            .collect::<Vec<_>>();
        dex_files.sort_by_key(|dex| dex.index);

        let dex_sequence_contiguous = dex_files
            .iter()
            .enumerate()
            .all(|(offset, dex)| dex.index == u32::try_from(offset + 1).unwrap_or(u32::MAX));

        let resource_prefix = format!("{module_name}/res/");
        let asset_prefix = format!("{module_name}/assets/");
        let native_prefix = format!("{module_name}/lib/");
        let mut native_abis = BTreeSet::new();
        let mut resource_entries = 0_usize;
        let mut asset_entries = 0_usize;
        let mut baseline_profile_present = false;
        let mut baseline_profile_metadata_present = false;

        for name in &names {
            if name.starts_with(&resource_prefix) {
                resource_entries = resource_entries.saturating_add(1);
            }
            if name.starts_with(&asset_prefix) {
                asset_entries = asset_entries.saturating_add(1);
            }
            if *name == format!("{module_name}/assets/dexopt/baseline.prof") {
                baseline_profile_present = true;
            }
            if *name == format!("{module_name}/assets/dexopt/baseline.profm") {
                baseline_profile_metadata_present = true;
            }
            if let Some(relative) = name.strip_prefix(&native_prefix) {
                if let Some((abi, _)) = relative.split_once('/') {
                    if !abi.is_empty() {
                        native_abis.insert(abi.to_owned());
                    }
                }
            }
        }

        modules.push(BundleModuleInspection {
            name: module_name,
            manifest_present: names.contains(manifest_name.as_str()),
            dex_files,
            dex_sequence_contiguous,
            resources_table_present: names.contains(resources_name.as_str()),
            resource_entries,
            asset_entries,
            native_abis,
            baseline_profile_present,
            baseline_profile_metadata_present,
        });
    }

    modules.sort_by(|left, right| {
        module_sort_key(&left.name)
            .cmp(&module_sort_key(&right.name))
            .then_with(|| left.name.cmp(&right.name))
    });

    let dynamic_features = modules
        .iter()
        .filter(|module| module.name != "base")
        .map(|module| module.name.clone())
        .collect::<Vec<_>>();

    let bundle_metadata_entries = names
        .iter()
        .filter(|name| name.starts_with("BUNDLE-METADATA/"))
        .count();

    Ok(AabInspection {
        file_size: fs::metadata(path)?.len(),
        sha256: sha256_file(path)?,
        entry_count: directory.entries.len(),
        bundle_config_present: names.contains(BUNDLE_CONFIG),
        modules,
        dynamic_features,
        bundle_metadata_entries,
    })
}

pub fn verify_aab_structure(path: &Path) -> Result<AabInspection> {
    let inspection = inspect_aab(path)?;

    if !inspection.bundle_config_present {
        return Err(PackageError::VerificationFailed(
            "AAB does not contain BundleConfig.pb".into(),
        ));
    }

    let base = inspection
        .modules
        .iter()
        .find(|module| module.name == "base")
        .ok_or_else(|| {
            PackageError::VerificationFailed(
                "AAB does not contain a base module manifest".into(),
            )
        })?;

    if !base.manifest_present {
        return Err(PackageError::VerificationFailed(format!(
            "AAB does not contain {BASE_MANIFEST}"
        )));
    }

    for module in &inspection.modules {
        if !module.manifest_present {
            return Err(PackageError::VerificationFailed(format!(
                "AAB module '{}' has no manifest",
                module.name
            )));
        }
        if !module.dex_sequence_contiguous {
            return Err(PackageError::VerificationFailed(format!(
                "AAB module '{}' contains a non-contiguous classes*.dex sequence",
                module.name
            )));
        }
    }

    Ok(inspection)
}

fn module_from_manifest(name: &str) -> Option<&str> {
    let suffix = "/manifest/AndroidManifest.xml";
    let module = name.strip_suffix(suffix)?;
    if module.is_empty() || module.contains('/') {
        return None;
    }
    Some(module)
}

fn dex_index(name: &str) -> Option<u32> {
    if name == "classes.dex" {
        return Some(1);
    }

    let number = name.strip_prefix("classes")?.strip_suffix(".dex")?;
    if number.is_empty() || number.starts_with('0') {
        return None;
    }
    let parsed = number.parse::<u32>().ok()?;
    (parsed >= 2).then_some(parsed)
}

fn module_sort_key(name: &str) -> (u8, &str) {
    if name == "base" {
        (0, name)
    } else {
        (1, name)
    }
}

#[cfg(test)]
mod tests {
    use super::{dex_index, module_from_manifest};

    #[test]
    fn module_manifest_paths_are_strict() {
        assert_eq!(
            module_from_manifest("base/manifest/AndroidManifest.xml"),
            Some("base")
        );
        assert_eq!(
            module_from_manifest("payments/manifest/AndroidManifest.xml"),
            Some("payments")
        );
        assert_eq!(
            module_from_manifest("nested/payments/manifest/AndroidManifest.xml"),
            None
        );
    }

    #[test]
    fn bundle_dex_names_are_canonical() {
        assert_eq!(dex_index("classes.dex"), Some(1));
        assert_eq!(dex_index("classes2.dex"), Some(2));
        assert_eq!(dex_index("classes02.dex"), None);
        assert_eq!(dex_index("other.dex"), None);
    }
}
