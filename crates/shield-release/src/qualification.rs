use crate::error::{ReleaseError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QualificationPolicy {
    pub schema: u32,
    pub required_rc_gates: Vec<String>,
    pub required_stable_gates: Vec<String>,
    pub minimum_external_reviewers: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedbackStatus {
    pub schema: u32,
    pub external_reviewers: usize,
    pub accepted_feedback_items: usize,
    pub blocking_findings_open: usize,
}

impl QualificationPolicy {
    pub fn load(path: &Path) -> Result<Self> {
        let value: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 {
            return Err(ReleaseError::InvalidQualification(
                "qualification policy schema must be 1".into(),
            ));
        }
        if self.minimum_external_reviewers == 0 {
            return Err(ReleaseError::InvalidQualification(
                "stable release requires at least one external reviewer".into(),
            ));
        }
        validate_gate_list("RC", &self.required_rc_gates)?;
        validate_gate_list("stable", &self.required_stable_gates)?;

        let stable = self.required_stable_gates.iter().collect::<BTreeSet<_>>();
        for gate in &self.required_rc_gates {
            if !stable.contains(gate) {
                return Err(ReleaseError::InvalidQualification(format!(
                    "stable policy must include RC gate '{gate}'"
                )));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn stable_feedback_satisfied(&self, feedback: &FeedbackStatus) -> bool {
        feedback.schema == 1
            && feedback.external_reviewers >= self.minimum_external_reviewers
            && feedback.blocking_findings_open == 0
    }
}

impl FeedbackStatus {
    pub fn load(path: &Path) -> Result<Self> {
        let value: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        if value.schema != 1 {
            return Err(ReleaseError::InvalidQualification(
                "feedback status schema must be 1".into(),
            ));
        }
        Ok(value)
    }
}

fn validate_gate_list(label: &str, gates: &[String]) -> Result<()> {
    if gates.is_empty() {
        return Err(ReleaseError::InvalidQualification(format!(
            "{label} gate list must not be empty"
        )));
    }
    let mut seen = BTreeSet::new();
    for gate in gates {
        if gate.trim().is_empty() || !seen.insert(gate) {
            return Err(ReleaseError::InvalidQualification(format!(
                "{label} gates must be non-empty and unique"
            )));
        }
    }
    Ok(())
}
