//! Phase O.1 diagnostic DEX transformation and verified ZIP32 reconstruction.
//! This unsigned staging artifact is never a production protection result.

use crate::{CoreError, ProductionBuildContext, Result, MAX_DEX_BYTES, MAX_TOTAL_DEX_BYTES};
use nexora_shield_dex::{canonical_dex_index, DexInput, MultiDexRewriteConfig, MultiDexSet};
use nexora_shield_package::{
    crc32_ieee, is_legacy_signature_entry, read_stored_entry, read_zip_directory,
    rewrite_stored_entries, verify_apk_structure, ZipDirectory,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

// Bind the validated multidex input set and its exact source bytes.
type LoadedDexSources = (Vec<DexInput>, BTreeMap<String, Vec<u8>>);

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
    /// Rebuilds an unsigned diagnostic APK, not a production-protected APK.
    ///
    /// # Errors
    ///
    /// Rejects unsafe destinations, changed input, invalid DEX data, no-op
    /// transformations and reconstructed artifacts that fail final checks.
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
        // Compare resolved paths rather than raw strings: aliases through
        // "./", ".." and symlinked parents must not bypass output isolation.
        // symlink_metadata catches dangling final-component symlinks as well.
        if fs::symlink_metadata(destination).is_ok()
            || crate::production::normalized_destination(destination)?
                == crate::production::normalized_destination(self.input())?
            || crate::production::normalized_destination(destination)?
                == crate::production::normalized_destination(self.output())?
        {
            return Err(CoreError::InvalidRequest(
                "DEX staging destination must be new and separate from source/output".into(),
            ));
        }
        // The preflight enforces conservative compatibility and class ownership.
        let _ = self.inspect_dex()?;
        let directory = read_zip_directory(self.input())?;
        let (inputs, originals) = self.load_dex_inputs(&directory)?;
        let set = MultiDexSet::parse(inputs).map_err(|error| {
            CoreError::InvalidRequest(format!("DEX staging validation: {error}"))
        })?;
        let outputs = set.rewrite(config).map_err(|error| {
            CoreError::InvalidRequest(format!("DEX transform refused: {error}"))
        })?;
        let mut result = StagedDexResult {
            dex_units: outputs.len(),
            changed_dex_units: 0,
            skipped_cross_dex_rename_units: 0,
            source_files_removed: 0,
            debug_info_detached: 0,
            name_records: 0,
            output_sha256: String::new(),
        };
        let mut replacements = BTreeMap::new();
        for unit in outputs {
            if unit.rename_skipped_for_cross_dex_reflection {
                result.skipped_cross_dex_rename_units += 1;
            }
            if let Some(report) = unit.rename_report {
                result.name_records += report.records.len();
            }
            if let Some(report) = unit.metadata_report {
                result.source_files_removed += report.source_files_removed;
                result.debug_info_detached += report.debug_info_detached;
            }
            if originals.get(&unit.name) != Some(&unit.bytes) {
                result.changed_dex_units += 1;
            }
            replacements.insert(unit.name, unit.bytes);
        }
        if result.changed_dex_units == 0 {
            return Err(CoreError::InvalidRequest(
                "requested DEX rewrite changed no bytes; no protection claimed".into(),
            ));
        }
        self.verify_input_unchanged()?;
        // The ZIP writer exclusively owns the new path and cleans its own
        // partial files; never remove a concurrently created path on refusal.
        rewrite_stored_entries(self.input(), destination, &replacements)?;
        let reconstruction = self.verify_staged_apk(destination, &directory, &replacements);
        match reconstruction {
            Ok(output_hash) => {
                result.output_sha256 = output_hash;
                Ok(result)
            }
            Err(error) => {
                let _ = fs::remove_file(destination);
                Err(error)
            }
        }
    }

    fn load_dex_inputs(
        &self,
        directory: &ZipDirectory,
    ) -> Result<LoadedDexSources> {
        let mut inputs = Vec::new();
        let mut originals = BTreeMap::new();
        let mut total = 0_usize;
        for entry in &directory.entries {
            if canonical_dex_index(&entry.name).is_none() {
                continue;
            }
            let size = usize::try_from(entry.uncompressed_size).map_err(|_| {
                CoreError::InvalidRequest("DEX size overflows host word width".into())
            })?;
            total = total
                .checked_add(size)
                .ok_or_else(|| CoreError::InvalidRequest("total DEX size overflow".into()))?;
            if size > MAX_DEX_BYTES || total > MAX_TOTAL_DEX_BYTES {
                return Err(CoreError::InvalidRequest(
                    "DEX staging exceeds preflight memory limit".into(),
                ));
            }
            let bytes =
                read_stored_entry(self.input(), entry, MAX_DEX_BYTES)?.ok_or_else(|| {
                    CoreError::InvalidRequest(format!(
                        "unsupported compressed DEX '{}'",
                        entry.name
                    ))
                })?;
            if crc32_ieee(&bytes) != entry.crc32 {
                return Err(CoreError::InvalidRequest(format!(
                    "DEX '{}' has an invalid ZIP CRC",
                    entry.name
                )));
            }
            originals.insert(entry.name.clone(), bytes.clone());
            inputs.push(DexInput {
                name: entry.name.clone(),
                bytes,
            });
        }
        self.verify_input_unchanged()?;
        Ok((inputs, originals))
    }

    fn verify_staged_apk(
        &self,
        destination: &Path,
        source: &ZipDirectory,
        replacements: &BTreeMap<String, Vec<u8>>,
    ) -> Result<String> {
        let inspection = verify_apk_structure(destination)?;
        if inspection.dex_files.len() != self.dex_count() {
            return Err(CoreError::InvalidRequest(
                "staged APK lost a DEX unit".into(),
            ));
        }
        let built = read_zip_directory(destination)?;
        verify_rebuilt_zip(source, &built, destination, replacements)?;
        let decoded = built
            .entries
            .iter()
            .filter(|entry| replacements.contains_key(&entry.name))
            .map(|entry| {
                read_stored_entry(destination, entry, MAX_DEX_BYTES)?
                    .ok_or_else(|| CoreError::InvalidRequest("DEX extraction failed".into()))
                    .map(|bytes| DexInput {
                        name: entry.name.clone(),
                        bytes,
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let reparsed = MultiDexSet::parse(decoded).map_err(|error| {
            CoreError::InvalidRequest(format!("staged APK DEX verification: {error}"))
        })?;
        if reparsed.units.len() != replacements.len() {
            return Err(CoreError::InvalidRequest(
                "staged DEX count mismatch".into(),
            ));
        }
        self.verify_input_unchanged()?;
        Ok(inspection.sha256)
    }
}

fn verify_rebuilt_zip(
    source: &ZipDirectory,
    built: &ZipDirectory,
    destination: &Path,
    replacements: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let mut observed = BTreeSet::new();
    for entry in &built.entries {
        if is_legacy_signature_entry(&entry.name) {
            return Err(CoreError::InvalidRequest(
                "staged APK contains stale signature data".into(),
            ));
        }
        if let Some(expected) = replacements.get(&entry.name) {
            let actual = read_stored_entry(destination, entry, MAX_DEX_BYTES)?
                .ok_or_else(|| CoreError::InvalidRequest("staged DEX is not stored".into()))?;
            if actual != *expected || crc32_ieee(&actual) != entry.crc32 {
                return Err(CoreError::InvalidRequest(format!(
                    "staged DEX '{}' differs from validated rewrite",
                    entry.name
                )));
            }
            observed.insert(entry.name.clone());
        } else {
            let original = source
                .entries
                .iter()
                .find(|candidate| candidate.name == entry.name)
                .ok_or_else(|| {
                    CoreError::InvalidRequest(format!("unexpected APK entry '{}'", entry.name))
                })?;
            if original.crc32 != entry.crc32
                || original.uncompressed_size != entry.uncompressed_size
                || original.compression_method != entry.compression_method
            {
                return Err(CoreError::InvalidRequest(format!(
                    "unmodified APK entry '{}' changed",
                    entry.name
                )));
            }
        }
    }
    if observed.len() != replacements.len()
        || built.entries.len()
            != source
                .entries
                .iter()
                .filter(|entry| !is_legacy_signature_entry(&entry.name))
                .count()
    {
        return Err(CoreError::InvalidRequest(
            "staged APK entry inventory mismatch".into(),
        ));
    }
    Ok(())
}
