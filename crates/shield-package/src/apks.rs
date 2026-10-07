use crate::error::{PackageError, Result};
use crate::hash::sha256_file;
use crate::zip::read_zip_directory;
use std::fs;
use std::path::Path;

const TOC: &str = "toc.pb";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitApkKind {
    Split,
    Standalone,
    Universal,
    Instant,
    System,
    AssetSlice,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitApkInspection {
    pub path: String,
    pub kind: SplitApkKind,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub crc32: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApkSetInspection {
    pub file_size: u64,
    pub sha256: String,
    pub entry_count: usize,
    pub toc_present: bool,
    pub apks: Vec<SplitApkInspection>,
}

pub fn inspect_apk_set(path: &Path) -> Result<ApkSetInspection> {
    let directory = read_zip_directory(path)?;
    let mut apks = directory
        .entries
        .iter()
        .filter(|entry| entry.name.ends_with(".apk"))
        .map(|entry| SplitApkInspection {
            path: entry.name.clone(),
            kind: classify_apk(&entry.name),
            compressed_size: entry.compressed_size,
            uncompressed_size: entry.uncompressed_size,
            crc32: entry.crc32,
        })
        .collect::<Vec<_>>();
    apks.sort_by(|left, right| left.path.cmp(&right.path));

    Ok(ApkSetInspection {
        file_size: fs::metadata(path)?.len(),
        sha256: sha256_file(path)?,
        entry_count: directory.entries.len(),
        toc_present: directory.entries.iter().any(|entry| entry.name == TOC),
        apks,
    })
}

pub fn verify_apk_set_structure(path: &Path) -> Result<ApkSetInspection> {
    let inspection = inspect_apk_set(path)?;
    if !inspection.toc_present {
        return Err(PackageError::VerificationFailed(
            "APK Set does not contain toc.pb".into(),
        ));
    }
    if inspection.apks.is_empty() {
        return Err(PackageError::VerificationFailed(
            "APK Set contains no APK artifacts".into(),
        ));
    }
    Ok(inspection)
}

fn classify_apk(path: &str) -> SplitApkKind {
    if path == "universal.apk" || path.ends_with("/universal.apk") {
        return SplitApkKind::Universal;
    }

    let root = path.split('/').next().unwrap_or_default();
    match root {
        "splits" => SplitApkKind::Split,
        "standalones" => SplitApkKind::Standalone,
        "instant" => SplitApkKind::Instant,
        "system" => SplitApkKind::System,
        "asset-slices" => SplitApkKind::AssetSlice,
        _ => SplitApkKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_apk, SplitApkKind};

    #[test]
    fn apk_set_paths_are_classified() {
        assert_eq!(classify_apk("splits/base-master.apk"), SplitApkKind::Split);
        assert_eq!(
            classify_apk("standalones/standalone-x86.apk"),
            SplitApkKind::Standalone
        );
        assert_eq!(classify_apk("universal.apk"), SplitApkKind::Universal);
        assert_eq!(classify_apk("other.apk"), SplitApkKind::Unknown);
    }
}
