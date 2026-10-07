use crate::policy::CompiledPolicy;
use crate::risk::{RiskAssessment, RiskLevel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RaspResponse {
    Continue,
    Report,
    RequireReverification,
    DenySensitiveOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseDecision {
    pub risk_level: RiskLevel,
    pub score: u32,
    pub response: RaspResponse,
    pub signals_evaluated: usize,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ResponseEngine;

impl ResponseEngine {
    #[must_use]
    pub fn decide(policy: &CompiledPolicy, assessment: &RiskAssessment) -> ResponseDecision {
        ResponseDecision {
            risk_level: assessment.level,
            score: assessment.score,
            response: policy.response_for(assessment.level),
            signals_evaluated: assessment.signals_evaluated,
        }
    }
}
