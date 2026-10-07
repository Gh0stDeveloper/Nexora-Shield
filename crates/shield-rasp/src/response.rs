use crate::policy::{CompiledPolicy, PolicyMode};
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
    pub configured_response: RaspResponse,
    pub effective_response: RaspResponse,
    pub policy_mode: PolicyMode,
    pub signals_evaluated: usize,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ResponseEngine;

impl ResponseEngine {
    #[must_use]
    pub fn decide(policy: &CompiledPolicy, assessment: &RiskAssessment) -> ResponseDecision {
        let configured_response = policy.response_for(assessment.level);
        let effective_response = match policy.mode() {
            PolicyMode::Enforce => configured_response,
            PolicyMode::ReportOnly => configured_response.min(RaspResponse::Report),
        };

        ResponseDecision {
            risk_level: assessment.level,
            score: assessment.score,
            configured_response,
            effective_response,
            policy_mode: policy.mode(),
            signals_evaluated: assessment.signals_evaluated,
        }
    }
}
