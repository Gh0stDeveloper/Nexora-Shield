use crate::error::{PackageError, Result};
use crate::hash::{sha256_file, to_hex, Sha256};
use crate::zip::{is_legacy_signature_entry, read_stored_entry, read_zip_directory, ZipEntry};
use std::fs;
use std::path::Path;

/// Format inferred for the packaged Android manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestFormat {
    BinaryXml,
    TextXml,
    UnknownStored,
    Compressed,
}

impl ManifestFormat {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BinaryXml => "binary-xml",
            Self::TextXml => "text-xml",
            Self::UnknownStored => "unknown-stored",
            Self::Compressed => "compressed-uninspected",
        }
    }
}

/// Manifest metadata available without decoding Android binary XML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestInspection {
    pub format: ManifestFormat,
    pub compression_method: u16,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub crc32: u32,
    pub content_sha256: Option<String>,
}

/// One root-level classes*.dex entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexFileInspection {
    pub name: String,
    pub index: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub crc32: u32,
}

/// Structural APK inspection produced by Phase A.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApkInspection {
    pub file_size: u64,
    pub sha256: String,
    pub entry_count: usize,
    pub manifest: ManifestInspection,
    pub dex_files: Vec<DexFileInspection>,
    pub dex_sequence_contiguous: bool,
    pub legacy_signature_entries: Vec<String>,
}

pub fn inspect_apk(path: &Path) -> Result<ApkInspection> {
    let directory = read_zip_directory(path)?;
    let manifest_entry = directory
        .entries
        .iter()
        .find(|entry| entry.name == "AndroidManifest.xml")
        .ok_or(PackageError::MissingManifest)?;

    let manifest = inspect_manifest(path, manifest_entry)?;
    let mut dex_files = directory
        .entries
        .iter()
        .filter_map(inspect_dex_entry)
        .collect::<Vec<_>>();
    dex_files.sort_by_key(|dex| dex.index);

    let dex_sequence_contiguous = dex_files
        .iter()
        .enumerate()
        .all(|(offset, dex)| dex.index == u32::try_from(offset + 1).unwrap_or(u32::MAX));

    let mut legacy_signature_entries = directory
        .entries
        .iter()
        .filter(|entry| is_legacy_signature_entry(&entry.name))
        .map(|entry| entry.name.clone())
        .collect::<Vec<_>>();
    legacy_signature_entries.sort();

    Ok(ApkInspection {
        file_size: fs::metadata(path)?.len(),
        sha256: sha256_file(path)?,
        entry_count: directory.entries.len(),
        manifest,
        dex_files,
        dex_sequence_contiguous,
        legacy_signature_entries,
    })
}

pub fn verify_apk_structure(path: &Path) -> Result<ApkInspection> {
    let inspection = inspect_apk(path)?;
    if !inspection.dex_sequence_contiguous {
        return Err(PackageError::VerificationFailed(
            "classes*.dex sequence contains a gap or invalid index".into(),
        ));
    }
    Ok(inspection)
}

fn inspect_manifest(path: &Path, entry: &ZipEntry) -> Result<ManifestInspection> {
    let content = read_stored_entry(path, entry, 16 * 1024 * 1024)?;
    let (format, content_sha256) = match content {
        Some(bytes) => {
            let format = detect_manifest_format(&bytes);
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            (format, Some(to_hex(&hasher.finalize())))
        }
        None => (ManifestFormat::Compressed, None),
    };

    Ok(ManifestInspection {
        format,
        compression_method: entry.compression_method,
        compressed_size: entry.compressed_size,
        uncompressed_size: entry.uncompressed_size,
        crc32: entry.crc32,
        content_sha256,
    })
}

fn detect_manifest_format(bytes: &[u8]) -> ManifestFormat {
    if bytes.starts_with(&[0x03, 0x00, 0x08, 0x00]) {
        return ManifestFormat::BinaryXml;
    }

    let first_non_whitespace = bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace());
    if first_non_whitespace == Some(b'<') {
        ManifestFormat::TextXml
    } else {
        ManifestFormat::UnknownStored
    }
}

fn inspect_dex_entry(entry: &ZipEntry) -> Option<DexFileInspection> {
    let index = dex_index(&entry.name)?;
    Some(DexFileInspection {
        name: entry.name.clone(),
        index,
        compressed_size: entry.compressed_size,
        uncompressed_size: entry.uncompressed_size,
        crc32: entry.crc32,
    })
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

#[cfg(test)]
mod tests {
    use super::{detect_manifest_format, dex_index, ManifestFormat};

    #[test]
    fn dex_names_are_discovered_strictly() {
        assert_eq!(dex_index("classes.dex"), Some(1));
        assert_eq!(dex_index("classes2.dex"), Some(2));
        assert_eq!(dex_index("classes10.dex"), Some(10));
        assert_eq!(dex_index("classes01.dex"), None);
        assert_eq!(dex_index("dir/classes2.dex"), None);
    }

    #[test]
    fn manifest_format_detection_handles_binary_and_text() {
        assert_eq!(
            detect_manifest_format(&[0x03, 0x00, 0x08, 0x00, 0, 0]),
            ManifestFormat::BinaryXml
        );
        assert_eq!(
            detect_manifest_format(b" \n<manifest/>"),
            ManifestFormat::TextXml
        );
        assert_eq!(
            detect_manifest_format(b"not xml"),
            ManifestFormat::UnknownStored
        );
    }
}
