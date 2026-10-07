use crate::error::{PackageError, Result};
use crate::hash::sha256_file;
use crate::zip::read_zip_directory;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const MANIFEST: &str = "AndroidManifest.xml";
const CLASSES_JAR: &str = "classes.jar";
const AAR_METADATA: &str = "META-INF/com/android/build/gradle/aar-metadata.properties";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AarInspection {
    pub file_size: u64,
    pub sha256: String,
    pub entry_count: usize,
    pub manifest_present: bool,
    pub classes_jar_present: bool,
    pub aar_metadata_present: bool,
    pub consumer_rule_entries: Vec<String>,
    pub resource_entries: usize,
    pub asset_entries: usize,
    pub jni_abis: BTreeSet<String>,
    pub resource_symbols_present: bool,
    pub baseline_profile_entries: Vec<String>,
}

pub fn inspect_aar(path: &Path) -> Result<AarInspection> {
    let directory = read_zip_directory(path)?;
    let names = directory
        .entries
        .iter()
        .map(|entry| entry.name.as_str())
        .collect::<BTreeSet<_>>();

    let mut consumer_rule_entries = names
        .iter()
        .filter(|name| is_consumer_rule(name))
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    consumer_rule_entries.sort();

    let mut baseline_profile_entries = names
        .iter()
        .filter(|name| is_baseline_profile(name))
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    baseline_profile_entries.sort();

    let mut jni_abis = BTreeSet::new();
    for name in &names {
        if let Some(relative) = name.strip_prefix("jni/") {
            if let Some((abi, _)) = relative.split_once('/') {
                if !abi.is_empty() {
                    jni_abis.insert(abi.to_owned());
                }
            }
        }
    }

    Ok(AarInspection {
        file_size: fs::metadata(path)?.len(),
        sha256: sha256_file(path)?,
        entry_count: directory.entries.len(),
        manifest_present: names.contains(MANIFEST),
        classes_jar_present: names.contains(CLASSES_JAR),
        aar_metadata_present: names.contains(AAR_METADATA),
        consumer_rule_entries,
        resource_entries: names
            .iter()
            .filter(|name| name.starts_with("res/"))
            .count(),
        asset_entries: names
            .iter()
            .filter(|name| name.starts_with("assets/"))
            .count(),
        jni_abis,
        resource_symbols_present: names.contains("R.txt"),
        baseline_profile_entries,
    })
}

pub fn verify_aar_structure(path: &Path) -> Result<AarInspection> {
    let inspection = inspect_aar(path)?;
    if !inspection.manifest_present {
        return Err(PackageError::VerificationFailed(
            "AAR does not contain AndroidManifest.xml".into(),
        ));
    }
    if !inspection.classes_jar_present {
        return Err(PackageError::VerificationFailed(
            "AAR does not contain classes.jar".into(),
        ));
    }
    Ok(inspection)
}

fn is_consumer_rule(name: &str) -> bool {
    matches!(
        name,
        "proguard.txt"
            | "consumer-rules.pro"
            | "META-INF/proguard/consumer-rules.pro"
            | "META-INF/com.android.tools/proguard/coroutines.pro"
    ) || name.starts_with("META-INF/proguard/")
}

fn is_baseline_profile(name: &str) -> bool {
    name == "baseline-prof.txt"
        || name == "startup-prof.txt"
        || name.ends_with("/baseline-prof.txt")
        || name.ends_with("/startup-prof.txt")
}

#[cfg(test)]
mod tests {
    use super::{is_baseline_profile, is_consumer_rule};

    #[test]
    fn consumer_rule_locations_are_detected() {
        assert!(is_consumer_rule("proguard.txt"));
        assert!(is_consumer_rule("META-INF/proguard/library.pro"));
        assert!(!is_consumer_rule("res/raw/proguard.txt"));
    }

    #[test]
    fn baseline_profile_locations_are_detected() {
        assert!(is_baseline_profile("baseline-prof.txt"));
        assert!(is_baseline_profile("profiles/baseline-prof.txt"));
        assert!(!is_baseline_profile("baseline.prof"));
    }
}
