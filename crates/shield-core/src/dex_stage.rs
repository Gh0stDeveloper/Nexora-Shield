//! Phase O.1 diagnostic DEX transformation and verified ZIP32 reconstruction.
//! This unsigned staging artifact is never a production protection result.

use crate::{CoreError, ProductionBuildContext, Result, MAX_DEX_BYTES, MAX_TOTAL_DEX_BYTES};
use nexora_shield_crypto::{seal_retrace_map, KeySchedule, RetraceMap, RetraceRecord};
use nexora_shield_dex::{canonical_dex_index, DexInput, MultiDexRewriteConfig, MultiDexSet};
use nexora_shield_package::{
    crc32_ieee, is_legacy_signature_entry, read_decoded_entry, read_stored_entry,
    read_zip_directory, rewrite_stored_entries, verify_apk_structure,
    verify_preserved_entry_payload, ZipDirectory,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
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
    pub verified_code_items: usize,
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
        self.stage_dex_rewrite_internal(destination, config, None)
    }

    /// Produce an unsigned diagnostic APK and a separate, encrypted retrace
    /// sidecar. A new 0600 Unix file is required; no key/plaintext is written.
    ///
    /// # Errors
    ///
    /// Rejects conflicting destinations, missing key material, no rename
    /// records, unsafe output, failed authentication or sidecar I/O.
    pub fn stage_dex_rewrite_with_protected_retrace(
        &self,
        destination: &Path,
        retrace_destination: &Path,
        config: &MultiDexRewriteConfig,
        key_schedule: &KeySchedule,
    ) -> Result<StagedDexResult> {
        self.stage_dex_rewrite_internal(
            destination,
            config,
            Some((retrace_destination, key_schedule)),
        )
    }

    fn stage_dex_rewrite_internal(
        &self,
        destination: &Path,
        config: &MultiDexRewriteConfig,
        retrace: Option<(&Path, &KeySchedule)>,
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
        if let Some((map_path, _)) = retrace {
            #[cfg(not(unix))]
            return Err(CoreError::InvalidRequest(
                "private retrace file permissions require Unix secure creation".into(),
            ));
            let normalized_map = crate::production::normalized_destination(map_path)?;
            if fs::symlink_metadata(map_path).is_ok()
                || [destination, self.input(), self.output()]
                    .iter()
                    .map(|path| crate::production::normalized_destination(path))
                    .collect::<Result<Vec<_>>>()?
                    .contains(&normalized_map)
            {
                return Err(CoreError::InvalidRequest(
                    "private retrace destination must be new and disjoint from APK files".into(),
                ));
            }
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
            verified_code_items: 0,
            output_sha256: String::new(),
        };
        let mut replacements = BTreeMap::new();
        let mut retrace_records = Vec::new();
        for unit in outputs {
            result.verified_code_items += unit.audit.preserved_code_items;
            if unit.rename_skipped_for_cross_dex_reflection {
                result.skipped_cross_dex_rename_units += 1;
            }
            if let Some(report) = unit.rename_report {
                result.name_records += report.records.len();
                if retrace.is_some() {
                    retrace_records.extend(report.records.into_iter().map(|record| {
                        RetraceRecord {
                            dex_name: unit.name.clone(),
                            string_idx: record.string_idx,
                            original: record.old,
                            obfuscated: record.new,
                            symbols: record.symbols,
                        }
                    }));
                }
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
        if retrace.is_some() && retrace_records.is_empty() {
            return Err(CoreError::InvalidRequest(
                "no renamed symbols; an empty protected retrace map is forbidden".into(),
            ));
        }
        self.verify_input_unchanged()?;
        // The ZIP writer exclusively owns the new path and cleans its own
        // partial files; never remove a concurrently created path on refusal.
        rewrite_stored_entries(self.input(), destination, &replacements)?;
        let reconstruction = self.verify_staged_apk(destination, &directory, &replacements);
        match reconstruction {
            Ok(output_hash) => {
                if let Some((map_path, schedule)) = retrace {
                    let encrypted = (|| -> Result<Vec<u8>> {
                        let document =
                            RetraceMap::new(schedule, output_hash.clone(), retrace_records)
                                .map_err(|_| {
                                    CoreError::InvalidRequest(
                                        "invalid private retrace mapping".into(),
                                    )
                                })?;
                        seal_retrace_map(schedule, &document).map_err(|_| {
                            CoreError::InvalidRequest(
                                "unable to seal private retrace mapping".into(),
                            )
                        })
                    })();
                    let written =
                        encrypted.and_then(|bytes| write_private_retrace(map_path, &bytes));
                    if let Err(error) = written {
                        let _ = fs::remove_file(destination);
                        return Err(error);
                    }
                }
                result.output_sha256 = output_hash;
                Ok(result)
            }
            Err(error) => {
                let _ = fs::remove_file(destination);
                Err(error)
            }
        }
    }

    fn load_dex_inputs(&self, directory: &ZipDirectory) -> Result<LoadedDexSources> {
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
            let bytes = read_decoded_entry(self.input(), entry, MAX_DEX_BYTES)?;
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
        verify_rebuilt_zip(self.input(), source, &built, destination, replacements)?;
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

/// Atomic no-overwrite semantics for the private sidecar's leaf. Never emit
/// plaintext and never overwrite a preexisting file or symlink.
#[cfg(unix)]
fn write_private_retrace(destination: &Path, ciphertext: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    let outcome = file.write_all(ciphertext).and_then(|()| file.sync_all());
    if let Err(error) = outcome {
        drop(file);
        let _ = fs::remove_file(destination);
        return Err(CoreError::Io(error));
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_private_retrace(_destination: &Path, _ciphertext: &[u8]) -> Result<()> {
    Err(CoreError::InvalidRequest(
        "private retrace sidecar requires Unix 0600 file permissions".into(),
    ))
}

fn verify_rebuilt_zip(
    source_path: &Path,
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
            // A CRC/size equality check alone cannot prove untouched bytes.
            // Compare the exact copied compressed payload in bounded chunks.
            verify_preserved_entry_payload(source_path, original, destination, entry)?;
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

#[cfg(all(test, unix))]
mod retrace_tests {
    use super::write_private_retrace;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn scratch() -> std::path::PathBuf {
        let unique = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "nexora-o13-retrace-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&dir).expect("unique test directory");
        dir
    }

    #[test]
    fn protected_sidecar_is_private_and_never_overwritten() {
        let dir = scratch();
        let path = dir.join("build.retrace.enc");
        write_private_retrace(&path, b"authenticated-container").expect("write private file");
        let permissions = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(permissions & 0o077, 0, "no group or world permissions");
        assert_eq!(fs::read(&path).expect("read"), b"authenticated-container");
        assert!(write_private_retrace(&path, b"overwrite-attempt").is_err());
        assert_eq!(
            fs::read(&path).expect("preserved"),
            b"authenticated-container"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn protected_sidecar_rejects_symlink_and_preserves_target() {
        let dir = scratch();
        let target = dir.join("target");
        let link = dir.join("protected-map");
        fs::write(&target, b"unchanged").expect("target");
        symlink(&target, &link).expect("link");
        assert!(write_private_retrace(&link, b"private-data").is_err());
        assert_eq!(fs::read(&target).expect("original target"), b"unchanged");
        fs::remove_dir_all(dir).expect("cleanup");
    }
}
