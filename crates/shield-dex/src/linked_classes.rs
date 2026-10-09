//! Coordinated, fixed-layout class descriptor remapping across DEX units.
//!
//! This intentionally does not attempt method/field remapping, which requires
//! binding by declaring class and signature. The output remains diagnostic.
use crate::compatibility::CompatibilityAnalyzer;
use crate::error::{DexError, Result};
use crate::model::ReferenceKind;
use crate::multidex::{DexInput, DexRewriteOutput, MultiDexRewriteConfig, MultiDexSet};
use crate::parser::DexParser;
use crate::transform::{DexRewriteVerifier, DexWriter, MetadataReducer, RenamePass, RenameRecord};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn rewrite_linked_classes(
    set: &MultiDexSet,
    config: &MultiDexRewriteConfig,
) -> Result<Vec<DexRewriteOutput>> {
    let rename = config.rename.as_ref().ok_or_else(|| {
        DexError::UnsafeRename("linked class rewrite requires rename policy".into())
    })?;
    let compatibility = set
        .units
        .iter()
        .map(|unit| CompatibilityAnalyzer::analyze(&unit.dex))
        .collect::<Result<Vec<_>>>()?;
    if config.conservative_cross_dex_reflection
        && compatibility
            .iter()
            .any(|report| report.reflection_detected)
    {
        let mut outputs = set.rewrite(&MultiDexRewriteConfig {
            rename: None,
            strip_metadata: config.strip_metadata,
            conservative_cross_dex_reflection: true,
        })?;
        for output in &mut outputs {
            output.rename_skipped_for_cross_dex_reflection = true;
        }
        return Ok(outputs);
    }

    // Derive *owner* names first. A reference-only DEX cannot mint another
    // spelling for the same class. The deterministic per-unit seed is retained.
    let mut plans = Vec::with_capacity(set.units.len());
    let mut global = BTreeMap::<String, String>::new();
    for unit in &set.units {
        let mut policy = rename.clone();
        policy.rename_methods = false;
        policy.rename_fields = false;
        policy.seed ^= u64::from(unit.index).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let planned = RenamePass::apply(&unit.dex, &policy)?;
        for class in &unit.dex.classes {
            let type_id = &unit.dex.types[class.class_idx as usize];
            if let Some(record) = planned
                .report
                .records
                .iter()
                .find(|record| record.string_idx == type_id.descriptor_idx)
            {
                if global
                    .insert(record.old.clone(), record.new.clone())
                    .is_some()
                {
                    return Err(DexError::UnsafeRename(
                        "duplicate global class rename owner".into(),
                    ));
                }
            }
        }
        plans.push(planned.report);
    }

    // Check generated targets against *all* original strings (including
    // unresolved SDK types, foreign classes and runtime literals), and each
    // other, before touching any output DEX.
    let reserved = set
        .units
        .iter()
        .flat_map(|unit| unit.dex.strings.iter().map(|s| s.value.as_str()))
        .collect::<BTreeSet<_>>();
    let mut new_names = BTreeSet::new();
    for target in global.values() {
        if reserved.contains(target.as_str()) || !new_names.insert(target) {
            return Err(DexError::UnsafeRename(format!(
                "renamed class descriptor {target} collides with a global DEX string"
            )));
        }
    }

    // Detect runtime class-name literals in *any* DEX, including dotted
    // Class.forName names. These strings are outside the type-id graph and
    // cannot safely be coordinated by a descriptor-only rewrite.
    for unit in &set.units {
        for code in unit.dex.code_items.values() {
            for instruction in &code.instructions {
                if let Some((ReferenceKind::String, index)) = instruction.reference {
                    if let Some(value) = unit.dex.string(index) {
                        if global.keys().any(|source| {
                            value == source
                                || value
                                    == source
                                        .strip_prefix('L')
                                        .and_then(|s| s.strip_suffix(';'))
                                        .unwrap_or(source)
                                        .replace('/', ".")
                        }) {
                            return Err(DexError::UnsafeRename(
                                "cross-DEX runtime class literal needs a keep rule".into(),
                            ));
                        }
                    }
                }
            }
        }
    }

    // Resolve defining owners and descriptor-based signatures before changing
    // any DEX string bytes. Reference-only method_ids/field_ids inherit that
    // global plan, while ambiguous or externally-bound aliases fail closed.
    let member_plan = crate::linked_members::plan(set, rename, &compatibility)?;
    let mut outputs = Vec::with_capacity(set.units.len());
    for (unit_index, ((unit, mut report), compatibility)) in
        set.units.iter().zip(plans).zip(&compatibility).enumerate()
    {
        let mut patches = BTreeMap::new();
        for (type_index, type_id) in unit.dex.types.iter().enumerate() {
            let source =
                unit.dex
                    .type_descriptor(type_index as u32)
                    .ok_or(DexError::InvalidIndex {
                        kind: "type",
                        index: type_index as u32,
                    })?;
            let component = source.trim_start_matches('[');
            let Some(target) = global.get(component) else {
                continue;
            };
            let prefix_len = source.len() - component.len();
            let replacement = format!("{}{target}", &source[..prefix_len]);
            if compatibility
                .protected_string_indices
                .contains(&type_id.descriptor_idx)
            {
                return Err(DexError::UnsafeRename(
                    "type descriptor is also a protected runtime/JNI literal".into(),
                ));
            }
            if let Some(existing) = patches.insert(type_id.descriptor_idx, replacement.clone()) {
                if existing != replacement {
                    return Err(DexError::UnsafeRename(
                        "one DEX string has incompatible descriptor bindings".into(),
                    ));
                }
            }
            if let Some(record) = report
                .records
                .iter()
                .find(|record| record.string_idx == type_id.descriptor_idx)
            {
                if record.old != source || record.new != replacement {
                    return Err(DexError::UnsafeRename(
                        "local class rename disagrees with global owner mapping".into(),
                    ));
                }
            } else {
                report.records.push(RenameRecord {
                    string_idx: type_id.descriptor_idx,
                    old: source.to_owned(),
                    new: replacement,
                    symbols: vec![format!("global-type-ref:{type_index}")],
                });
            }
        }
        // Merge member references with class descriptor patches. The fixed-
        // layout writer cannot fork a single shared string ID.
        for (index, member) in &member_plan.patches[unit_index] {
            if patches.insert(*index, member.new.clone()).is_some() {
                return Err(DexError::UnsafeRename(
                    "member rewrite shares a string ID with a class descriptor".into(),
                ));
            }
            let old = unit.dex.string(*index).ok_or(DexError::InvalidIndex {
                kind: "string",
                index: *index,
            })?;
            report.records.push(RenameRecord {
                string_idx: *index,
                old: old.to_owned(),
                new: member.new.clone(),
                symbols: member.symbols.clone(),
            });
        }
        report.skipped_contract_names.extend(&member_plan.skipped[unit_index]);
        report.skipped_contract_names.sort_unstable();
        report.skipped_contract_names.dedup();
        report.records.sort_by_key(|record| record.string_idx);
        let mut current = DexWriter::patch_strings(&unit.dex, &patches)?;
        let mut metadata_report = None;
        if config.strip_metadata {
            let parsed = DexParser::parse(&current)?;
            let (bytes, metadata) = MetadataReducer::strip_debug_metadata(&parsed)?;
            current = bytes;
            metadata_report = Some(metadata);
        }
        let audit = DexRewriteVerifier::verify(
            &unit.dex,
            &current,
            Some(&report),
            metadata_report.as_ref(),
        )?;
        outputs.push(DexRewriteOutput {
            name: unit.name.clone(),
            bytes: current,
            rename_report: Some(report),
            metadata_report,
            rename_skipped_for_cross_dex_reflection: false,
            audit,
        });
    }

    // Verify canonical numbering and exactly one class owner after remapping.
    MultiDexSet::parse(
        outputs
            .iter()
            .map(|output| DexInput {
                name: output.name.clone(),
                bytes: output.bytes.clone(),
            })
            .collect(),
    )?;
    Ok(outputs)
}
