//! Read-only DEX inspection for the Phase O.1 production planner.
//!
//! Extraction is bounded. Unsupported compressed DEX entries are rejected
//! rather than silently skipped or counted as protected.

use crate::{CoreError, ProductionBuildContext, Result};
use nexora_shield_dex::{
    canonical_dex_index, CompatibilityAnalyzer, DexInput, MultiDexSet, SelectorResolver,
};
use nexora_shield_package::{read_stored_entry, read_zip_directory, sha256_file};
use std::collections::BTreeSet;

/// Maximum decoded size accepted for one DEX file in this first O.1 pass.
pub const MAX_DEX_BYTES: usize = 64 * 1024 * 1024;
/// Maximum combined DEX size to cap parser memory consumption.
pub const MAX_TOTAL_DEX_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexUnitPreflight {
    pub name: String,
    pub class_count: usize,
    pub method_count: usize,
    pub field_count: usize,
    pub selected_classes: usize,
    pub selected_methods: usize,
    pub selected_fields: usize,
    pub reflection_detected: bool,
    pub native_method_count: usize,
    pub protected_string_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexPreflight {
    pub units: Vec<DexUnitPreflight>,
    pub total_decoded_bytes: usize,
    pub inspected_input_sha256: String,
}

impl ProductionBuildContext {
    /// Parses and validates every canonical stored DEX from the source APK,
    /// checks cross-DEX class ownership, then runs conservative compatibility
    /// and default selector resolution. No files are modified.
    ///
    /// Deflated DEX is explicitly unsupported by this preliminary reader,
    /// not considered inspected. A future bounded decompressor must replace
    /// that limitation before O.1 can be closed.
    ///
    /// # Errors
    ///
    /// Fails on input substitution, non-STORE DEX, size limits, malformed DEX,
    /// duplicated class definitions or inconsistent DEX inventory.
    pub fn inspect_dex(&self) -> Result<DexPreflight> {
        self.verify_input_unchanged()?;
        let directory = read_zip_directory(self.input())?;
        let mut inputs = Vec::new();
        let mut total_decoded_bytes = 0_usize;

        for entry in directory.entries {
            if canonical_dex_index(&entry.name).is_none() {
                continue;
            }
            let decoded_size = usize::try_from(entry.uncompressed_size)
                .map_err(|_| CoreError::InvalidRequest("DEX size exceeds host limits".into()))?;
            if decoded_size > MAX_DEX_BYTES {
                return Err(CoreError::InvalidRequest(format!(
                    "DEX '{}' exceeds the {} byte inspection limit",
                    entry.name, MAX_DEX_BYTES
                )));
            }
            total_decoded_bytes = total_decoded_bytes
                .checked_add(decoded_size)
                .ok_or_else(|| CoreError::InvalidRequest("combined DEX size overflow".into()))?;
            if total_decoded_bytes > MAX_TOTAL_DEX_BYTES {
                return Err(CoreError::InvalidRequest(
                    "combined DEX size exceeds preflight memory budget".into(),
                ));
            }
            let bytes =
                read_stored_entry(self.input(), &entry, MAX_DEX_BYTES)?.ok_or_else(|| {
                    CoreError::InvalidRequest(format!(
                        "DEX '{}' must use ZIP STORE for O.1 preflight; compressed DEX is unsupported",
                        entry.name
                    ))
                })?;
            if bytes.len() != decoded_size {
                return Err(CoreError::InvalidRequest(format!(
                    "DEX '{}' size does not match ZIP metadata",
                    entry.name
                )));
            }
            inputs.push(DexInput {
                name: entry.name,
                bytes,
            });
        }

        if inputs.len() != self.dex_count() {
            return Err(CoreError::InvalidRequest(
                "DEX inventory changed after immutable planning".into(),
            ));
        }
        let set = MultiDexSet::parse(inputs)
            .map_err(|error| CoreError::InvalidRequest(format!("DEX validation: {error}")))?;
        let mut descriptors = BTreeSet::new();
        let mut units = Vec::with_capacity(set.units.len());
        for unit in &set.units {
            for class in &unit.dex.classes {
                let descriptor = unit.dex.type_descriptor(class.class_idx).ok_or_else(|| {
                    CoreError::InvalidRequest(format!(
                        "DEX '{}' contains a class without a descriptor",
                        unit.name
                    ))
                })?;
                if !descriptors.insert(descriptor.to_owned()) {
                    return Err(CoreError::InvalidRequest(format!(
                        "duplicate class definition across DEX: {descriptor}"
                    )));
                }
            }
            let compatibility = CompatibilityAnalyzer::analyze(&unit.dex).map_err(|error| {
                CoreError::InvalidRequest(format!(
                    "DEX '{}' compatibility analysis: {error}",
                    unit.name
                ))
            })?;
            // No configured selectors yet: the current contract selects all
            // available user-code targets. This is not a transform.
            let selection = SelectorResolver::resolve(&unit.dex, &[]).map_err(|error| {
                CoreError::InvalidRequest(format!("DEX '{}' selector analysis: {error}", unit.name))
            })?;
            units.push(DexUnitPreflight {
                name: unit.name.clone(),
                class_count: unit.dex.classes.len(),
                method_count: unit.dex.methods.len(),
                field_count: unit.dex.fields.len(),
                selected_classes: selection.classes.len(),
                selected_methods: selection.methods.len(),
                selected_fields: selection.fields.len(),
                reflection_detected: compatibility.reflection_detected,
                native_method_count: compatibility.native_methods.len(),
                protected_string_count: compatibility.protected_string_indices.len(),
            });
        }

        // Detect ordinary changes to input bytes while analysis was running.
        // Execution still has to repeat identity validation at its boundary.
        self.verify_input_unchanged()?;
        Ok(DexPreflight {
            units,
            total_decoded_bytes,
            inspected_input_sha256: self.input_sha256().to_owned(),
        })
    }

    /// Verify preflight input identity before handing off to a new stage.
    ///
    /// # Errors
    ///
    /// Fails if source APK content changed since creation of the plan.
    pub fn verify_input_unchanged(&self) -> Result<()> {
        let hash = sha256_file(self.input())?;
        if hash != self.input_sha256() {
            return Err(CoreError::InvalidRequest(
                "input APK changed after production plan creation".into(),
            ));
        }
        Ok(())
    }
}
