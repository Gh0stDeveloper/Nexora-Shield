use crate::error::{LabError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditRequirement {
    ThreatModel,
    SecurityPolicy,
    PhaseChecklists,
    RegressionCorpus,
    BenchmarkMethodology,
    CiEvidence,
}

impl AuditRequirement {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ThreatModel => "threat model",
            Self::SecurityPolicy => "security policy",
            Self::PhaseChecklists => "phase checklists",
            Self::RegressionCorpus => "regression corpus",
            Self::BenchmarkMethodology => "benchmark methodology",
            Self::CiEvidence => "CI evidence",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvidenceClass {
    Public,
    Confidential,
    SecretReferenceOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvidenceItem {
    pub id: String,
    pub relative_path: String,
    pub class: AuditEvidenceClass,
    pub redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReadinessInput {
    pub requirements_present: BTreeSet<AuditRequirement>,
    pub evidence: Vec<AuditEvidenceItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReadinessReport {
    pub ready: bool,
    pub missing_requirements: Vec<String>,
    pub unsafe_evidence: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AuditPreparation;

impl AuditPreparation {
    pub fn evaluate(input: &AuditReadinessInput) -> Result<AuditReadinessReport> {
        let required = [
            AuditRequirement::ThreatModel,
            AuditRequirement::SecurityPolicy,
            AuditRequirement::PhaseChecklists,
            AuditRequirement::RegressionCorpus,
            AuditRequirement::BenchmarkMethodology,
            AuditRequirement::CiEvidence,
        ];
        let missing_requirements = required
            .into_iter()
            .filter(|requirement| !input.requirements_present.contains(requirement))
            .map(|requirement| requirement.label().to_owned())
            .collect::<Vec<_>>();

        let mut unsafe_evidence = Vec::new();
        for evidence in &input.evidence {
            if evidence.id.trim().is_empty() || evidence.relative_path.trim().is_empty() {
                return Err(LabError::InvalidAuditInput(
                    "audit evidence requires id and relative path".into(),
                ));
            }
            if evidence.relative_path.starts_with('/')
                || evidence.relative_path.contains("../")
                || evidence.relative_path.contains("..\\")
            {
                return Err(LabError::InvalidAuditInput(format!(
                    "unsafe evidence path '{}'",
                    evidence.relative_path
                )));
            }
            if evidence.class != AuditEvidenceClass::Public && !evidence.redacted {
                unsafe_evidence.push(evidence.id.clone());
            }
        }

        Ok(AuditReadinessReport {
            ready: missing_requirements.is_empty() && unsafe_evidence.is_empty(),
            missing_requirements,
            unsafe_evidence,
        })
    }
}
