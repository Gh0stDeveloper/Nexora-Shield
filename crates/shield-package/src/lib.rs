//! APK/ZIP packaging primitives for Nexora Shield.
//!
//! Phase A deliberately avoids third-party parser dependencies in the trusted
//! packaging boundary. The normalizer supports standard ZIP32 APKs using stored
//! or DEFLATE entries and copies compressed payloads byte-for-byte.

#![forbid(unsafe_code)]

mod aab;
mod aar;
mod apk;
mod apks;
mod bundletool;
mod error;
mod hash;
mod tools;
mod zip;

pub use aab::{
    inspect_aab, verify_aab_structure, AabInspection, BundleBaselineProfile, BundleDexInspection,
    BundleModuleInspection,
};
pub use aar::{inspect_aar, verify_aar_structure, AarInspection, AarMarker};
pub use apk::{
    inspect_apk, verify_apk_structure, ApkInspection, DexFileInspection, ManifestFormat,
    ManifestInspection,
};
pub use apks::{
    inspect_apk_set, verify_apk_set_structure, ApkSetInspection, SplitApkInspection, SplitApkKind,
};
pub use bundletool::{ApkSetMode, Bundletool, BundletoolSigningConfig};
pub use error::{PackageError, Result};
pub use hash::sha256_file;
pub use tools::{AndroidTools, SigningConfig};
pub use zip::{
    crc32_ieee, is_legacy_signature_entry, normalize_zip, read_decoded_entry, read_stored_entry, read_zip_directory,
    rewrite_stored_entries, verify_normalized_equivalence, verify_preserved_entry_payload, NormalizationSummary, ZipDirectory,
    ZipEntry,
};
