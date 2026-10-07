use crate::error::{LabError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureRule {
    pub id: String,
    pub needle: String,
    pub maximum_occurrences: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureFinding {
    pub rule_id: String,
    pub occurrences: usize,
    pub maximum_occurrences: usize,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticExposureReport {
    pub artifact_label: String,
    pub bytes_scanned: usize,
    pub findings: Vec<ExposureFinding>,
}

impl StaticExposureReport {
    #[must_use]
    pub fn passed(&self) -> bool {
        self.findings.iter().all(|finding| finding.passed)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StaticExposureHarness;

impl StaticExposureHarness {
    pub fn scan(
        artifact_label: impl Into<String>,
        bytes: &[u8],
        rules: &[ExposureRule],
    ) -> Result<StaticExposureReport> {
        let mut findings = Vec::with_capacity(rules.len());
        for rule in rules {
            if rule.id.trim().is_empty() {
                return Err(LabError::InvalidRule("rule id must not be blank".into()));
            }
            if rule.needle.is_empty() {
                return Err(LabError::InvalidRule(format!(
                    "rule '{}' has an empty needle",
                    rule.id
                )));
            }
            let occurrences = count_occurrences(bytes, rule.needle.as_bytes());
            findings.push(ExposureFinding {
                rule_id: rule.id.clone(),
                occurrences,
                maximum_occurrences: rule.maximum_occurrences,
                passed: occurrences <= rule.maximum_occurrences,
            });
        }

        Ok(StaticExposureReport {
            artifact_label: artifact_label.into(),
            bytes_scanned: bytes.len(),
            findings,
        })
    }
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.len() > haystack.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}
