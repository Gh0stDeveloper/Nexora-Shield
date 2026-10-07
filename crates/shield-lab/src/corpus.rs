use crate::error::{LabError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegressionCategory {
    StaticExposure,
    Repack,
    ReSign,
    RuntimeInstrumentation,
    ModifiedEnvironment,
    BypassPortability,
    Fuzz,
    Performance,
    RegressionCorpus,
    SecurityScore,
    ComparativeBenchmark,
    ExternalAudit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionCase {
    pub id: String,
    pub category: RegressionCategory,
    pub description: String,
    pub expected: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionCorpus {
    pub schema: u32,
    pub cases: Vec<RegressionCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionCoverageEntry {
    pub case_id: String,
    pub gate: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionCoverage {
    pub schema: u32,
    pub entries: Vec<RegressionCoverageEntry>,
}

impl RegressionCoverage {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        let coverage: Self = serde_json::from_slice(&bytes)?;
        if coverage.schema != 1 {
            return Err(LabError::InvalidCorpus(format!(
                "unsupported coverage schema {}",
                coverage.schema
            )));
        }
        Ok(coverage)
    }

    pub fn validate_against(&self, corpus: &RegressionCorpus) -> Result<()> {
        corpus.validate()?;
        if self.schema != 1 {
            return Err(LabError::InvalidCorpus(format!(
                "unsupported coverage schema {}",
                self.schema
            )));
        }

        let corpus_ids = corpus
            .cases
            .iter()
            .map(|case| case.id.as_str())
            .collect::<BTreeSet<_>>();
        let mut covered_ids = BTreeSet::new();

        for entry in &self.entries {
            if entry.gate.trim().is_empty() {
                return Err(LabError::InvalidCorpus(format!(
                    "coverage for '{}' has an empty gate",
                    entry.case_id
                )));
            }
            if !corpus_ids.contains(entry.case_id.as_str()) {
                return Err(LabError::InvalidCorpus(format!(
                    "coverage references unknown case '{}'",
                    entry.case_id
                )));
            }
            if !covered_ids.insert(entry.case_id.as_str()) {
                return Err(LabError::InvalidCorpus(format!(
                    "duplicate coverage for case '{}'",
                    entry.case_id
                )));
            }
        }

        let missing = corpus_ids
            .difference(&covered_ids)
            .copied()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(LabError::InvalidCorpus(format!(
                "corpus cases without CI coverage: {}",
                missing.join(", ")
            )));
        }
        Ok(())
    }
}

impl RegressionCorpus {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        let corpus: Self = serde_json::from_slice(&bytes)?;
        corpus.validate()?;
        Ok(corpus)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 {
            return Err(LabError::InvalidCorpus(format!(
                "unsupported corpus schema {}",
                self.schema
            )));
        }
        if self.cases.is_empty() {
            return Err(LabError::InvalidCorpus("corpus must not be empty".into()));
        }

        let mut ids = BTreeSet::new();
        for case in &self.cases {
            if !valid_case_id(&case.id) {
                return Err(LabError::InvalidCorpus(format!(
                    "case id '{}' is invalid",
                    case.id
                )));
            }
            if !ids.insert(case.id.clone()) {
                return Err(LabError::InvalidCorpus(format!(
                    "duplicate case id '{}'",
                    case.id
                )));
            }
            if case.description.trim().is_empty() || case.expected.trim().is_empty() {
                return Err(LabError::InvalidCorpus(format!(
                    "case '{}' requires description and expected outcome",
                    case.id
                )));
            }
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        let mut hasher = Sha256::new();
        hasher.update(b"nexora-shield/security-lab-corpus/v1");
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }
}

fn valid_case_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 96
        && id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}
