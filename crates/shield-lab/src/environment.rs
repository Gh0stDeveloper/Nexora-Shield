use nexora_shield_rasp::{
    CompiledPolicy, EmulatorEvaluator, EmulatorObservation, ModifiedSystemEvaluator,
    ModifiedSystemObservation, ResponseEngine, RiskEngine, RiskLevel, RaspResponse, SignalSet,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifiedEnvironmentCase {
    pub name: String,
    pub system: ModifiedSystemObservation,
    pub emulator: EmulatorObservation,
    pub minimum_risk: RiskLevel,
    pub minimum_response: RaspResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModifiedEnvironmentResult {
    pub name: String,
    pub risk: RiskLevel,
    pub response: RaspResponse,
    pub signals: usize,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModifiedEnvironmentReport {
    pub cases_total: usize,
    pub cases_passed: usize,
    pub results: Vec<ModifiedEnvironmentResult>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ModifiedEnvironmentLab;

impl ModifiedEnvironmentLab {
    #[must_use]
    pub fn run(
        policy: &CompiledPolicy,
        cases: &[ModifiedEnvironmentCase],
    ) -> ModifiedEnvironmentReport {
        let risk_engine = RiskEngine::new(policy.thresholds());
        let mut results = Vec::with_capacity(cases.len());
        let mut cases_passed = 0_usize;

        for case in cases {
            let mut signals = SignalSet::default();
            signals.extend(ModifiedSystemEvaluator::evaluate(&case.system).signals().iter().cloned());
            signals.extend(EmulatorEvaluator::evaluate(&case.emulator).signals().iter().cloned());
            let assessment = risk_engine.evaluate(&signals);
            let decision = ResponseEngine::decide(policy, &assessment);
            let passed = assessment.level >= case.minimum_risk
                && decision.effective_response >= case.minimum_response;
            if passed {
                cases_passed = cases_passed.saturating_add(1);
            }
            results.push(ModifiedEnvironmentResult {
                name: case.name.clone(),
                risk: assessment.level,
                response: decision.effective_response,
                signals: assessment.signals_evaluated,
                passed,
            });
        }

        ModifiedEnvironmentReport {
            cases_total: cases.len(),
            cases_passed,
            results,
        }
    }
}
