use crate::checksum::refresh_integrity;
use crate::compatibility::{CompatibilityAnalyzer, CompatibilityReport};
use crate::error::{DexError, Result};
use crate::model::{DexFile, NO_INDEX};
use crate::parser::DexParser;
use crate::selector::{Selection, Selector, SelectorResolver};
use crate::validator::DexValidator;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, Clone, Copy)]
pub struct DexWriter;

impl DexWriter {
    pub fn round_trip(dex: &DexFile) -> Result<Vec<u8>> {
        let mut output = dex.bytes.clone();
        refresh_integrity(&mut output)?;
        let reparsed = DexParser::parse(&output)?;
        let _ = DexValidator::validate(&reparsed)?;
        Ok(output)
    }

    pub fn patch_strings(dex: &DexFile, patches: &BTreeMap<u32, String>) -> Result<Vec<u8>> {
        let mut output = dex.bytes.clone();

        for (string_idx, replacement) in patches {
            let string = dex
                .strings
                .get(*string_idx as usize)
                .ok_or(DexError::InvalidIndex {
                    kind: "string",
                    index: *string_idx,
                })?;

            if !string.value.is_ascii() || !replacement.is_ascii() {
                return Err(DexError::UnsafeRename(format!(
                    "string {string_idx} is not ASCII; Phase B fixed-layout writer refuses it"
                )));
            }
            if replacement.as_bytes().contains(&0) {
                return Err(DexError::UnsafeRename(format!(
                    "string {string_idx} replacement contains NUL"
                )));
            }
            if replacement.len() != string.byte_len as usize
                || replacement.encode_utf16().count() != string.utf16_len as usize
            {
                return Err(DexError::UnsafeRename(format!(
                    "string {string_idx} replacement must preserve MUTF-8 and UTF-16 length"
                )));
            }

            let start = string.data_start as usize;
            let end = start + string.byte_len as usize;
            if end > output.len() {
                return Err(DexError::InvalidOffset {
                    context: "string patch".into(),
                    offset: string.data_start,
                });
            }
            output[start..end].copy_from_slice(replacement.as_bytes());
        }

        refresh_integrity(&mut output)?;
        let reparsed = DexParser::parse(&output)?;
        let _ = DexValidator::validate(&reparsed)?;
        Ok(output)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataReductionReport {
    pub source_files_removed: usize,
    pub debug_info_detached: usize,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MetadataReducer;

impl MetadataReducer {
    pub fn strip_debug_metadata(dex: &DexFile) -> Result<(Vec<u8>, MetadataReductionReport)> {
        let mut output = dex.bytes.clone();
        let mut source_files_removed = 0_usize;
        let mut debug_info_detached = 0_usize;

        for (index, class) in dex.classes.iter().enumerate() {
            if class.source_file_idx == NO_INDEX {
                continue;
            }
            let offset = dex.header.class_defs_off as usize + index * 32 + 16;
            write_u32(&mut output, offset, NO_INDEX)?;
            source_files_removed += 1;
        }

        for code in dex.code_items.values() {
            if code.debug_info_off == 0 {
                continue;
            }
            write_u32(&mut output, code.offset as usize + 8, 0)?;
            debug_info_detached += 1;
        }

        refresh_integrity(&mut output)?;
        let reparsed = DexParser::parse(&output)?;
        let _ = DexValidator::validate(&reparsed)?;

        Ok((
            output,
            MetadataReductionReport {
                source_files_removed,
                debug_info_detached,
            },
        ))
    }
}

/// Proof that a diagnostic DEX rewrite only touched declared metadata or
/// fixed-width symbol strings. In particular, executable bytecode is immutable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexRewriteAudit {
    pub changed_symbol_strings: usize,
    pub source_files_removed: usize,
    pub debug_info_detached: usize,
    pub preserved_code_items: usize,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DexRewriteVerifier;

impl DexRewriteVerifier {
    /// Compare a rewritten DEX byte-for-byte against its validated source.
    /// Every mutation must be accounted for by the rename/metadata reports.
    ///
    /// # Errors
    ///
    /// Rejects unreported byte changes, mismatched reports, changes to executable
    /// code, altered tables or invalid rewritten DEX.
    pub fn verify(
        original: &DexFile,
        rewritten: &[u8],
        rename: Option<&RenameReport>,
        metadata: Option<&MetadataReductionReport>,
    ) -> Result<DexRewriteAudit> {
        if original.bytes.len() != rewritten.len() {
            return Err(DexError::UnsafeRename(
                "rewritten DEX changed file length".into(),
            ));
        }
        let parsed = DexParser::parse(rewritten)?;
        let _ = DexValidator::validate(&parsed)?;
        if original.strings.len() != parsed.strings.len()
            || original.types != parsed.types
            || original.protos != parsed.protos
            || original.fields != parsed.fields
            || original.methods != parsed.methods
            || original.classes.len() != parsed.classes.len()
            || original.class_data != parsed.class_data
            || original.code_items.len() != parsed.code_items.len()
        {
            return Err(DexError::UnsafeRename(
                "rewritten DEX changed structural ownership or table layout".into(),
            ));
        }
        let mut allowed = vec![false; rewritten.len()];
        allowed[8..32].fill(true); // Adler-32 and SHA-1 are recalculated.
        let mut changed_symbol_strings = 0_usize;
        if let Some(report) = rename {
            let mut reported_indices = BTreeSet::new();
            for record in &report.records {
                if !reported_indices.insert(record.string_idx) {
                    return Err(DexError::UnsafeRename("duplicate rename record".into()));
                }
                let source = original.strings.get(record.string_idx as usize).ok_or(
                    DexError::InvalidIndex {
                        kind: "string",
                        index: record.string_idx,
                    },
                )?;
                let target = parsed.strings.get(record.string_idx as usize).ok_or(
                    DexError::InvalidIndex {
                        kind: "string",
                        index: record.string_idx,
                    },
                )?;
                if source.value != record.old
                    || target.value != record.new
                    || record.old == record.new
                    || source.byte_len != target.byte_len
                    || source.data_start != target.data_start
                {
                    return Err(DexError::UnsafeRename(
                        "rename report does not match rewritten string bytes".into(),
                    ));
                }
                let start = source.data_start as usize;
                let end = start + source.byte_len as usize;
                if end > allowed.len() {
                    return Err(DexError::UnsafeRename("rename offset outside DEX".into()));
                }
                allowed[start..end].fill(true);
                changed_symbol_strings += 1;
            }
        }
        let mut source_files_removed = 0_usize;
        for (index, (before, after)) in original.classes.iter().zip(&parsed.classes).enumerate() {
            if before.source_file_idx != after.source_file_idx {
                if metadata.is_none()
                    || before.source_file_idx == NO_INDEX
                    || after.source_file_idx != NO_INDEX
                {
                    return Err(DexError::UnsafeRename(
                        "unexpected class source-file modification".into(),
                    ));
                }
                let offset = original.header.class_defs_off as usize + index * 32 + 16;
                allowed[offset..offset + 4].fill(true);
                source_files_removed += 1;
            }
        }
        let mut debug_info_detached = 0_usize;
        for (offset, before) in &original.code_items {
            let after = parsed
                .code_items
                .get(offset)
                .ok_or_else(|| DexError::UnsafeRename("rewritten DEX lost a code item".into()))?;
            if before.insns != after.insns
                || before.instructions != after.instructions
                || before.tries != after.tries
                || before.handlers != after.handlers
                || before.registers_size != after.registers_size
                || before.ins_size != after.ins_size
                || before.outs_size != after.outs_size
                || before.tries_size != after.tries_size
            {
                return Err(DexError::UnsafeRename(
                    "rewritten DEX changed executable code".into(),
                ));
            }
            if before.debug_info_off != after.debug_info_off {
                if metadata.is_none() || before.debug_info_off == 0 || after.debug_info_off != 0 {
                    return Err(DexError::UnsafeRename(
                        "unexpected code debug-info modification".into(),
                    ));
                }
                let start = *offset as usize + 8;
                allowed[start..start + 4].fill(true);
                debug_info_detached += 1;
            }
        }
        if let Some(report) = metadata {
            if report.source_files_removed != source_files_removed
                || report.debug_info_detached != debug_info_detached
            {
                return Err(DexError::UnsafeRename(
                    "metadata removal report differs from rewritten bytes".into(),
                ));
            }
        }
        if original
            .bytes
            .iter()
            .zip(rewritten)
            .enumerate()
            .any(|(index, (before, after))| before != after && !allowed[index])
        {
            return Err(DexError::UnsafeRename(
                "unreported DEX byte mutation outside declared transform regions".into(),
            ));
        }
        Ok(DexRewriteAudit {
            changed_symbol_strings,
            source_files_removed,
            debug_info_detached,
            preserved_code_items: original.code_items.len(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameConfig {
    pub selectors: Vec<Selector>,
    pub seed: u64,
    pub rename_classes: bool,
    pub rename_methods: bool,
    pub rename_fields: bool,
}

impl Default for RenameConfig {
    fn default() -> Self {
        Self {
            selectors: Vec::new(),
            seed: 0x4e45_584f_5241_5348,
            rename_classes: true,
            rename_methods: true,
            rename_fields: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameRecord {
    pub string_idx: u32,
    pub old: String,
    pub new: String,
    pub symbols: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RenameReport {
    pub records: Vec<RenameRecord>,
    pub skipped_protected: Vec<u32>,
    pub skipped_shared: Vec<u32>,
    pub skipped_contract_names: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameResult {
    pub bytes: Vec<u8>,
    pub report: RenameReport,
    pub compatibility: CompatibilityReport,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RenamePass;

impl RenamePass {
    pub fn apply(dex: &DexFile, config: &RenameConfig) -> Result<RenameResult> {
        let selection = SelectorResolver::resolve(dex, &config.selectors)?;
        let compatibility = CompatibilityAnalyzer::analyze(dex)?;
        let mut report = RenameReport::default();
        let users = collect_name_users(dex);
        let mut existing = dex
            .strings
            .iter()
            .map(|string| string.value.clone())
            .collect::<BTreeSet<_>>();
        let mut patches = BTreeMap::new();

        for (string_idx, symbols) in users {
            let old = dex.string(string_idx).ok_or(DexError::InvalidIndex {
                kind: "string",
                index: string_idx,
            })?;

            if compatibility.protected_string_indices.contains(&string_idx) {
                report.skipped_protected.push(string_idx);
                continue;
            }
            if is_contract_name(old) {
                report.skipped_contract_names.push(string_idx);
                continue;
            }

            let selected = symbols
                .iter()
                .filter(|symbol| symbol_enabled(**symbol, &selection, config))
                .count();
            if selected == 0 {
                continue;
            }
            if selected != symbols.len() {
                report.skipped_shared.push(string_idx);
                continue;
            }

            let class_descriptor = symbols
                .iter()
                .any(|symbol| matches!(symbol, SymbolUse::Class(_)));
            let mut salt = 0_u64;
            let replacement = loop {
                let candidate =
                    generate_replacement(old, class_descriptor, config.seed, string_idx, salt)?;
                if candidate != old && !existing.contains(&candidate) {
                    break candidate;
                }
                salt = salt.checked_add(1).ok_or_else(|| {
                    DexError::UnsafeRename("rename collision salt overflow".into())
                })?;
                if salt > 10_000 {
                    return Err(DexError::UnsafeRename(format!(
                        "unable to find collision-free replacement for string {string_idx}"
                    )));
                }
            };

            existing.insert(replacement.clone());
            patches.insert(string_idx, replacement.clone());
            report.records.push(RenameRecord {
                string_idx,
                old: old.to_owned(),
                new: replacement,
                symbols: symbols.iter().map(|symbol| (*symbol).label()).collect(),
            });
        }

        report.skipped_protected.sort_unstable();
        report.skipped_protected.dedup();
        report.skipped_shared.sort_unstable();
        report.skipped_shared.dedup();
        report.skipped_contract_names.sort_unstable();
        report.skipped_contract_names.dedup();

        let bytes = DexWriter::patch_strings(dex, &patches)?;
        Ok(RenameResult {
            bytes,
            report,
            compatibility,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymbolUse {
    Class(u32),
    Method(u32),
    Field(u32),
}

impl SymbolUse {
    fn label(self) -> String {
        match self {
            Self::Class(index) => format!("class:{index}"),
            Self::Method(index) => format!("method:{index}"),
            Self::Field(index) => format!("field:{index}"),
        }
    }
}

fn collect_name_users(dex: &DexFile) -> BTreeMap<u32, Vec<SymbolUse>> {
    let mut users = BTreeMap::<u32, Vec<SymbolUse>>::new();

    for class in &dex.classes {
        if let Some(type_id) = dex.types.get(class.class_idx as usize) {
            users
                .entry(type_id.descriptor_idx)
                .or_default()
                .push(SymbolUse::Class(class.class_idx));
        }
    }
    for (index, method) in dex.methods.iter().enumerate() {
        users
            .entry(method.name_idx)
            .or_default()
            .push(SymbolUse::Method(index as u32));
    }
    for (index, field) in dex.fields.iter().enumerate() {
        users
            .entry(field.name_idx)
            .or_default()
            .push(SymbolUse::Field(index as u32));
    }

    users
}

fn symbol_enabled(symbol: SymbolUse, selection: &Selection, config: &RenameConfig) -> bool {
    match symbol {
        SymbolUse::Class(index) => config.rename_classes && selection.classes.contains(&index),
        SymbolUse::Method(index) => config.rename_methods && selection.methods.contains(&index),
        SymbolUse::Field(index) => config.rename_fields && selection.fields.contains(&index),
    }
}

fn is_contract_name(value: &str) -> bool {
    matches!(
        value,
        "<init>"
            | "<clinit>"
            | "CREATOR"
            | "serialVersionUID"
            | "writeToParcel"
            | "describeContents"
            | "onCreate"
            | "onStart"
            | "onResume"
            | "onPause"
            | "onStop"
            | "onDestroy"
    )
}

fn generate_replacement(
    original: &str,
    class_descriptor: bool,
    seed: u64,
    string_idx: u32,
    salt: u64,
) -> Result<String> {
    if original.is_empty() || !original.is_ascii() {
        return Err(DexError::UnsafeRename(
            "only non-empty ASCII identifiers are eligible in Phase B".into(),
        ));
    }

    if class_descriptor {
        let Some(body) = original
            .strip_prefix('L')
            .and_then(|value| value.strip_suffix(';'))
        else {
            return Err(DexError::UnsafeRename(format!(
                "class descriptor '{original}' is not canonical"
            )));
        };
        let split = body.rfind('/').map_or(0, |index| index + 1);
        let prefix = &original[..=split];
        let simple = &body[split..];
        if simple.is_empty() {
            return Err(DexError::UnsafeRename(
                "class descriptor has an empty simple name".into(),
            ));
        }
        let token = token_like(simple, seed, string_idx, salt);
        return Ok(format!("{prefix}{token};"));
    }

    if original.starts_with('<') || original.ends_with('>') {
        return Err(DexError::UnsafeRename(format!(
            "special method name '{original}' cannot be renamed"
        )));
    }
    Ok(token_like(original, seed, string_idx, salt))
}

fn token_like(original: &str, seed: u64, string_idx: u32, salt: u64) -> String {
    let mut state = seed
        ^ u64::from(string_idx).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ salt.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    let mut output = String::with_capacity(original.len());

    for (position, original_byte) in original.bytes().enumerate() {
        if original_byte == b'$' {
            output.push('$');
            continue;
        }
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let mixed = state.wrapping_mul(0x2545_f491_4f6c_dd1d);
        let byte = if position == 0 {
            b'a' + (mixed % 26) as u8
        } else {
            const ALPHABET: &[u8; 37] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
            ALPHABET[(mixed % ALPHABET.len() as u64) as usize]
        };
        output.push(char::from(byte));
    }

    output
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| DexError::InvalidOffset {
            context: "u32 write overflow".into(),
            offset: offset as u32,
        })?;
    let destination = bytes
        .get_mut(offset..end)
        .ok_or_else(|| DexError::InvalidOffset {
            context: "u32 write".into(),
            offset: offset as u32,
        })?;
    destination.copy_from_slice(&value.to_le_bytes());
    Ok(())
}
