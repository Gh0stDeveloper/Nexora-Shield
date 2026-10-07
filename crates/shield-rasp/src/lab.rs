use crate::policy::CompiledPolicy;
use crate::response::{RaspResponse, ResponseEngine};
use crate::risk::{RiskEngine, RiskLevel};
use crate::signal::SignalSet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FalsePositiveCase {
    pub name: String,
    pub signals: SignalSet,
    pub maximum_risk: RiskLevel,
    pub maximum_response: RaspResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalsePositiveCaseResult {
    pub name: String,
    pub observed_risk: RiskLevel,
    pub observed_response: RaspResponse,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalsePositiveLabReport {
    pub cases_total: usize,
    pub cases_passed: usize,
    pub failures: Vec<FalsePositiveCaseResult>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FalsePositiveLab;

impl FalsePositiveLab {
    #[must_use]
    pub fn run(policy: &CompiledPolicy, cases: &[FalsePositiveCase]) -> FalsePositiveLabReport {
        let engine = RiskEngine::new(policy.thresholds());
        let mut failures = Vec::new();
        let mut passed = 0_usize;

        for case in cases {
            let assessment = engine.evaluate(&case.signals);
            let decision = ResponseEngine::decide(policy, &assessment);
            let case_passed = assessment.level <= case.maximum_risk
                && decision.effective_response <= case.maximum_response;

            if case_passed {
                passed = passed.saturating_add(1);
            } else {
                failures.push(FalsePositiveCaseResult {
                    name: case.name.clone(),
                    observed_risk: assessment.level,
                    observed_response: decision.effective_response,
                    passed: false,
                });
            }
        }

        FalsePositiveLabReport {
            cases_total: cases.len(),
            cases_passed: passed,
            failures,
        }
    }
}
