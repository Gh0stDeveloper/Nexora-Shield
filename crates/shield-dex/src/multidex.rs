use crate::compatibility::CompatibilityAnalyzer;
use crate::error::{DexError, Result};
use crate::model::DexFile;
use crate::parser::DexParser;
use crate::transform::{
    DexWriter, MetadataReducer, MetadataReductionReport, RenameConfig, RenamePass, RenameReport,
};
use crate::validator::DexValidator;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexInput {
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexUnit {
    pub name: String,
    pub index: u32,
    pub dex: DexFile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiDexSet {
    pub units: Vec<DexUnit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiDexRewriteConfig {
    pub rename: Option<RenameConfig>,
    pub strip_metadata: bool,
    pub conservative_cross_dex_reflection: bool,
}

impl Default for MultiDexRewriteConfig {
    fn default() -> Self {
        Self {
            rename: None,
            strip_metadata: false,
            conservative_cross_dex_reflection: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexRewriteOutput {
    pub name: String,
    pub bytes: Vec<u8>,
    pub rename_report: Option<RenameReport>,
    pub metadata_report: Option<MetadataReductionReport>,
    pub rename_skipped_for_cross_dex_reflection: bool,
}

impl MultiDexSet {
    pub fn parse(inputs: Vec<DexInput>) -> Result<Self> {
        if inputs.is_empty() {
            return Err(DexError::InvalidMultiDex(
                "at least classes.dex is required".into(),
            ));
        }

        let mut units = Vec::with_capacity(inputs.len());
        for input in inputs {
            let index = canonical_dex_index(&input.name).ok_or_else(|| {
                DexError::InvalidMultiDex(format!(
                    "'{}' is not a canonical classes*.dex name",
                    input.name
                ))
            })?;
            let dex = DexParser::parse(&input.bytes)?;
            let _ = DexValidator::validate(&dex)?;
            units.push(DexUnit {
                name: input.name,
                index,
                dex,
            });
        }

        units.sort_by_key(|unit| unit.index);
        for (offset, unit) in units.iter().enumerate() {
            let expected = u32::try_from(offset + 1)
                .map_err(|_| DexError::InvalidMultiDex("DEX count exceeds u32".into()))?;
            if unit.index != expected {
                return Err(DexError::InvalidMultiDex(format!(
                    "expected {}, found {}",
                    canonical_dex_name(expected),
                    unit.name
                )));
            }
        }

        Ok(Self { units })
    }

    pub fn rewrite(&self, config: &MultiDexRewriteConfig) -> Result<Vec<DexRewriteOutput>> {
        let cross_dex_reflection = config.conservative_cross_dex_reflection
            && self.units.len() > 1
            && self
                .units
                .iter()
                .map(|unit| CompatibilityAnalyzer::analyze(&unit.dex))
                .collect::<Result<Vec<_>>>()?
                .iter()
                .any(|report| report.reflection_detected);

        let mut outputs = Vec::with_capacity(self.units.len());
        for unit in &self.units {
            let mut current = DexWriter::round_trip(&unit.dex)?;
            let mut rename_report = None;
            let mut metadata_report = None;
            let mut rename_skipped = false;

            if let Some(rename) = &config.rename {
                if cross_dex_reflection {
                    rename_skipped = true;
                } else {
                    let parsed = DexParser::parse(&current)?;
                    let result = RenamePass::apply(&parsed, rename)?;
                    current = result.bytes;
                    rename_report = Some(result.report);
                }
            }

            if config.strip_metadata {
                let parsed = DexParser::parse(&current)?;
                let (bytes, report) = MetadataReducer::strip_debug_metadata(&parsed)?;
                current = bytes;
                metadata_report = Some(report);
            }

            let final_dex = DexParser::parse(&current)?;
            let _ = DexValidator::validate(&final_dex)?;
            outputs.push(DexRewriteOutput {
                name: unit.name.clone(),
                bytes: current,
                rename_report,
                metadata_report,
                rename_skipped_for_cross_dex_reflection: rename_skipped,
            });
        }

        Ok(outputs)
    }
}

#[must_use]
pub fn canonical_dex_index(name: &str) -> Option<u32> {
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

#[must_use]
pub fn canonical_dex_name(index: u32) -> String {
    if index == 1 {
        "classes.dex".into()
    } else {
        format!("classes{index}.dex")
    }
}

#[cfg(test)]
mod tests {
    use super::{canonical_dex_index, canonical_dex_name};

    #[test]
    fn canonical_names_are_strict() {
        assert_eq!(canonical_dex_index("classes.dex"), Some(1));
        assert_eq!(canonical_dex_index("classes2.dex"), Some(2));
        assert_eq!(canonical_dex_index("classes02.dex"), None);
        assert_eq!(canonical_dex_name(1), "classes.dex");
        assert_eq!(canonical_dex_name(3), "classes3.dex");
    }
}
