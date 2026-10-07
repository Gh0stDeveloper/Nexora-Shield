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
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'-' | b'_')
        })
}
