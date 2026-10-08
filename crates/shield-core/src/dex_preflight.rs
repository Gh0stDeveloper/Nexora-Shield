//! Read-only DEX inspection for the Phase O.1 production planner.
//!
//! Extraction is bounded. ZIP STORE and DEFLATE are decoded with byte limits
//! and checksum verification; unsupported/malformed DEX fails closed.

use crate::{CoreError, DexSelectorPolicy, ProductionBuildContext, Result};
use nexora_shield_dex::{
    canonical_dex_index, CompatibilityAnalyzer, DexInput, MultiDexSet, Selection, Selector,
    SelectorResolver,
};
use nexora_shield_package::{read_decoded_entry, read_zip_directory, sha256_file};


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
    pub dex_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexPreflight {
    pub units: Vec<DexUnitPreflight>,
    pub total_decoded_bytes: usize,
    pub inspected_input_sha256: String,
    /// Reflection detected in any unit of a multidex APK requires conservative
    /// cross-unit transformation policy; this is only an advisory preflight bit.
    pub cross_dex_reflection_risk: bool,
}

impl ProductionBuildContext {
    /// Parses and validates every canonical DEX from the source APK,
    /// checks cross-DEX class ownership, then runs conservative compatibility
    /// and default selector resolution. No files are modified.
    ///
    /// STORE and DEFLATE DEX decoding are bounded and checked against ZIP
    /// size and CRC metadata, but this remains a read-only diagnostic.
    ///
    /// # Errors
    ///
    /// Fails on input substitution, unsupported compression, size limits, malformed DEX,
    /// duplicated class definitions or inconsistent DEX inventory.
    pub fn inspect_dex(&self) -> Result<DexPreflight> {
        self.inspect_dex_with_selectors(&DexSelectorPolicy::default())
    }

    /// Inspect with bounded, explicit include/exclude rules. Selector matching
    /// is resolved globally across all DEX units; unmatched rules and empty
    /// effective selections are refused, rather than silently ignoring typos.
    ///
    /// # Errors
    ///
    /// Rejects malformed APK/DEX, stale inputs, unsupported selectors or
    /// empty effective selection without creating output or report files.
    pub fn inspect_dex_with_selectors(&self, policy: &DexSelectorPolicy) -> Result<DexPreflight> {
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
            let bytes = read_decoded_entry(self.input(), &entry, MAX_DEX_BYTES)?;
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
        let mut selected = vec![Selection::default(); set.units.len()];
        if policy.includes().is_empty() {
            for (slot, unit) in selected.iter_mut().zip(&set.units) {
                *slot = SelectorResolver::resolve(&unit.dex, &[]).map_err(|error| {
                    CoreError::InvalidRequest(format!("DEX selector resolution: {error}"))
                })?;
            }
        }
        for selector in policy.includes() {
            let matches = resolve_selector_across_dex(&set, selector)?;
            if matches.iter().all(Selection::is_empty) {
                return Err(CoreError::InvalidRequest(format!(
                    "include selector matched no defined DEX symbols: {}",
                    selector.class_pattern
                )));
            }
            for (slot, matches) in selected.iter_mut().zip(matches) {
                slot.union_with(&matches);
            }
        }
        for selector in policy.excludes() {
            let matches = resolve_selector_across_dex(&set, selector)?;
            if matches.iter().all(Selection::is_empty) {
                return Err(CoreError::InvalidRequest(format!(
                    "exclude selector matched no defined DEX symbols: {}",
                    selector.class_pattern
                )));
            }
            for (slot, matches) in selected.iter_mut().zip(matches) {
                slot.subtract(&matches);
            }
        }
        if selected.iter().all(Selection::is_empty) {
            return Err(CoreError::InvalidRequest(
                "effective DEX selector selection is empty".into(),
            ));
        }

        let mut units = Vec::with_capacity(set.units.len());
        let mut reflection_count = 0_usize;
        for (unit, selection) in set.units.iter().zip(selected) {
            let compatibility = CompatibilityAnalyzer::analyze(&unit.dex).map_err(|error| {
                CoreError::InvalidRequest(format!(
                    "DEX '{}' compatibility analysis: {error}",
                    unit.name
                ))
            })?;
            if compatibility.reflection_detected {
                reflection_count += 1;
            }
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
                dex_version: unit.dex.header.version.clone(),
            });
        }

        // Detect ordinary changes to input bytes while analysis was running.
        // Execution still has to repeat identity validation at its boundary.
        self.verify_input_unchanged()?;
        Ok(DexPreflight {
            units,
            total_decoded_bytes,
            inspected_input_sha256: self.input_sha256().to_owned(),
            cross_dex_reflection_risk: set.units.len() > 1 && reflection_count > 0,
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

fn resolve_selector_across_dex(
    set: &MultiDexSet,
    selector: &Selector,
) -> Result<Vec<Selection>> {
    let mut selections = Vec::with_capacity(set.units.len());
    for unit in &set.units {
        let matched = SelectorResolver::resolve(&unit.dex, std::slice::from_ref(selector))
            .map_err(|error| {
                CoreError::InvalidRequest(format!(
                    "DEX '{}' selector resolution: {error}",
                    unit.name
                ))
            })?;
        selections.push(matched);
    }
    Ok(selections)
}
