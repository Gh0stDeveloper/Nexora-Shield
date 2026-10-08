//! Preliminary Phase O.1 DEX transformation and ZIP reconstruction.
//!
//! This API emits a **staging artifact**, not a production protected APK. It
//! intentionally does not perform final runtime binding, signing or release.

use crate::{CoreError, ProductionBuildContext, Result, MAX_DEX_BYTES, MAX_TOTAL_DEX_BYTES};
use nexora_shield_dex::{
    canonical_dex_index, DexInput, MultiDexRewriteConfig, MultiDexSet,
};
use nexora_shield_package::{
    crc32_ieee, is_legacy_signature_entry, read_stored_entry, read_zip_directory,
    rewrite_stored_entries, verify_apk_structure,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedDexResult {
    pub dex_units: usize,
    pub changed_dex_units: usize,
    pub skipped_cross_dex_rename_units: usize,
    pub source_files_removed: usize,
    pub debug_info_detached: usize,
    pub name_records: usize,
    pub output_sha256: String,
}

impl ProductionBuildContext {
    /// Reconstructs a **diagnostic** APK containing rewritten DEX. The
    /// destination must be a private, previously nonexistent staging file.
    /// It is NOT an implementation of the release production orchestrator.
    ///
    /// # Errors
    ///
    /// Refuses unsafe paths, corrupt/stale inputs, unsupported DEX compression,
    /// no-op transformations, invalid output ZIP metadata or invalid final DEX.
    pub fn stage_dex_rewrite(
        &self,
        destination: &Path,
        config: &MultiDexRewriteConfig,
    ) -> Result<StagedDexResult> {
        if config.rename.is_none() && !config.strip_metadata {
            return Err(CoreError::InvalidRequest(
                "staging requires a real DEX transform".into(),
            ));
        }
        if destination.exists() || destination == self.input() || destination == self.output() {
            return Err(CoreError::InvalidRequest(
                "DEX staging destination must be new and separate from all source/output paths"
                    .into(),
            ));
        }
        // Verify exact source identity and semantic compatibility before
        // processing. The public preflight enforces cross-DEX uniqueness.
        let _ = self.inspect_dex()?;
        let directory = read_zip_directory(self.input())?;
        let mut inputs = Vec::new();
        let mut originals = BTreeMap::new();
        let mut total = 0_usize;
        for entry in directory.entries.iter() {
            if canonical_dex_index(&entry.name).is_none() {
                continue;
            }
            let size = usize::try_from(entry.uncompressed_size).map_err(|_| {
                CoreError::InvalidRequest("DEX size overflows host word width".into())
            })?;
            total = total.checked_add(size).ok_or_else(|| {
                CoreError::InvalidRequest("total DEX size overflow".into())
            })?;
            if size > MAX_DEX_BYTES || total > MAX_TOTAL_DEX_BYTES {
                return Err(CoreError::InvalidRequest(
                    "DEX staging exceeds preflight memory limit".into(),
                ));
            }
            let bytes = read_stored_entry(self.input(), entry, MAX_DEX_BYTES)?.ok_or_else(|| {
                CoreError::InvalidRequest(format!("unsupported compressed DEX '{}'", entry.name))
            })?;
            if crc32_ieee(&bytes) != entry.crc32 {
                return Err(CoreError::InvalidRequest(format!(
                    "DEX '{}' has an invalid ZIP CRC", entry.name
                )));
            }
            originals.insert(entry.name.clone(), bytes.clone());
            inputs.push(DexInput {
                name: entry.name.clone(),
                bytes,
            });
        }
        self.verify_input_unchanged()?;
        let set = MultiDexSet::parse(inputs).map_err(|error| {
            CoreError::InvalidRequest(format!("DEX staging validation: {error}"))
        })?;
        let mut replacements = BTreeMap::new();
        let mut changed = 0_usize;
        let mut skipped = 0_usize;
        let mut removed = 0_usize;
        let mut detached = 0_usize;
        let mut renamed = 0_usize;
        let outputs = set.rewrite(config).map_err(|error| {
            CoreError::InvalidRequest(format!("DEX transform refused: {error}"))
        })?;
        for unit in &outputs {
            if unit.rename_skipped_for_cross_dex_reflection {
                skipped += 1;
            }
            if let Some(report) = &unit.rename_report {
                renamed += report.records.len();
            }
            if let Some(report) = &unit.metadata_report {
                removed += report.source_files_removed;
                detached += report.debug_info_detached;
            }
            if originals.get(&unit.name) != Some(&unit.bytes) {
                changed += 1;
            }
            replacements.insert(unit.name.clone(), unit.bytes.clone());
        }
        if changed == 0 {
            return Err(CoreError::InvalidRequest(
                "requested DEX rewrite changed no bytes; no protection claimed".into(),
            ));
        }

        // A second check closes the common input-substitution window before
        // reconstruction. Runtime signing and final publication still require
        // their own independent source-snapshot contract.
        self.verify_input_unchanged()?;
        let reconstruction = (|| -> Result<StagedDexResult> {
            rewrite_stored_entries(self.input(), destination, &replacements)?;
            let inspection = verify_apk_structure(destination)?;
            if inspection.dex_files.len() != self.dex_count() {
                return Err(CoreError::InvalidRequest(
                    "staged APK lost a DEX unit".into(),
                ));
            }
            let built = read_zip_directory(destination)?;
            let mut observed = BTreeSet::new();
            for entry in &built.entries {
                if is_legacy_signature_entry(&entry.name) {
                    return Err(CoreError::InvalidRequest(
                        "staged APK contains stale signature data".into(),
                    ));
                }
                if let Some(expected) = replacements.get(&entry.name) {
                    let actual = read_stored_entry(destination, entry, MAX_DEX_BYTES)?.ok_or_else(
                        || CoreError::InvalidRequest("staged DEX is not stored".into()),
                    )?;
                    if actual != *expected || crc32_ieee(&actual) != entry.crc32 {
                        return Err(CoreError::InvalidRequest(format!(
                            "staged DEX '{}' differs from validated rewrite",
                            entry.name
                        )));
                    }
                    observed.insert(entry.name.clone());
                } else {
                    let source = directory.entries.iter().find(|candidate| {
                        candidate.name == entry.name
                    }).ok_or_else(|| {
                        CoreError::InvalidRequest(format!(
                            "unexpected APK entry '{}'", entry.name
                        ))
                    })?;
                    if source.crc32 != entry.crc32
                        || source.uncompressed_size != entry.uncompressed_size
                        || source.compression_method != entry.compression_method
                    {
                        return Err(CoreError::InvalidRequest(format!(
                            "unmodified APK entry '{}' changed", entry.name
                        )));
                    }
                }
            }
            if observed.len() != replacements.len()
                || built.entries.len()
                    != directory
                        .entries
                        .iter()
                        .filter(|entry| !is_legacy_signature_entry(&entry.name))
                        .count()
            {
                return Err(CoreError::InvalidRequest(
                    "staged APK entry inventory mismatch".into(),
                ));
            }
            let verified = MultiDexSet::parse(
                built.entries
                    .iter()
                    .filter(|entry| replacements.contains_key(&entry.name))
                    .map(|entry| {
                        read_stored_entry(destination, entry, MAX_DEX_BYTES)
                            .map_err(CoreError::from)
                            .and_then(|value| {
                                value.ok_or_else(|| {
                                    CoreError::InvalidRequest("DEX extraction failed".into())
                                })
                            })
                            .map(|bytes| DexInput {
                                name: entry.name.clone(),
                                bytes,
                            })
                    })
                    .collect::<Result<Vec<_>>>()?,
            )
            .map_err(|error| {
                CoreError::InvalidRequest(format!("staged APK DEX verification: {error}"))
            })?;
            if verified.units.len() != replacements.len() {
                return Err(CoreError::InvalidRequest(
                    "staged DEX count mismatch".into(),
                ));
            }
            Ok(StagedDexResult {
                dex_units: outputs.len(),
                changed_dex_units: changed,
                skipped_cross_dex_rename_units: skipped,
                source_files_removed: removed,
                debug_info_detached: detached,
                name_records: renamed,
                output_sha256: inspection.sha256,
            })
        })();
        if reconstruction.is_err() {
            let _ = fs::remove_file(destination);
        }
        reconstruction
    }
}
