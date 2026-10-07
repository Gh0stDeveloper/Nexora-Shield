use crate::error::{LabError, Result};
use serde::{Deserialize, Serialize};

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
    pub threat_model_present: bool,
    pub security_policy_present: bool,
    pub phase_checklists_present: bool,
    pub regression_corpus_present: bool,
    pub benchmark_methodology_present: bool,
    pub ci_evidence_present: bool,
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
        let mut missing_requirements = Vec::new();
        if !input.threat_model_present {
            missing_requirements.push("threat model".to_owned());
        }
        if !input.security_policy_present {
            missing_requirements.push("security policy".to_owned());
        }
        if !input.phase_checklists_present {
            missing_requirements.push("phase checklists".to_owned());
        }
        if !input.regression_corpus_present {
            missing_requirements.push("regression corpus".to_owned());
        }
        if !input.benchmark_methodology_present {
            missing_requirements.push("benchmark methodology".to_owned());
        }
        if !input.ci_evidence_present {
            missing_requirements.push("CI evidence".to_owned());
        }

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
