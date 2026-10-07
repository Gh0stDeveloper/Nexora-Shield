use nexora_shield_rasp::{
    CompiledPolicy, HookInjectionEvaluator, HookInjectionObservation, InstrumentationEvaluator,
    InstrumentationObservation, ResponseEngine, RiskEngine, RiskLevel, RaspResponse, SignalSet,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInstrumentationCase {
    pub name: String,
    pub instrumentation: InstrumentationObservation,
    pub hooks: HookInjectionObservation,
    pub minimum_risk: RiskLevel,
    pub minimum_response: RaspResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInstrumentationResult {
    pub name: String,
    pub risk: RiskLevel,
    pub score: u32,
    pub response: RaspResponse,
    pub signals: usize,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInstrumentationReport {
    pub cases_total: usize,
    pub cases_passed: usize,
    pub results: Vec<RuntimeInstrumentationResult>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RuntimeInstrumentationLab;

impl RuntimeInstrumentationLab {
    #[must_use]
    pub fn run(
        policy: &CompiledPolicy,
        cases: &[RuntimeInstrumentationCase],
    ) -> RuntimeInstrumentationReport {
        let risk_engine = RiskEngine::new(policy.thresholds());
        let mut results = Vec::with_capacity(cases.len());
        let mut cases_passed = 0_usize;

        for case in cases {
            let mut signals = SignalSet::default();
            signals.extend(InstrumentationEvaluator::evaluate(&case.instrumentation).signals().iter().cloned());
            signals.extend(HookInjectionEvaluator::evaluate(&case.hooks).signals().iter().cloned());
            let assessment = risk_engine.evaluate(&signals);
            let decision = ResponseEngine::decide(policy, &assessment);
            let passed = assessment.level >= case.minimum_risk
                && decision.effective_response >= case.minimum_response;
            if passed {
                cases_passed = cases_passed.saturating_add(1);
            }
            results.push(RuntimeInstrumentationResult {
                name: case.name.clone(),
                risk: assessment.level,
                score: assessment.score,
                response: decision.effective_response,
                signals: assessment.signals_evaluated,
                passed,
            });
        }

        RuntimeInstrumentationReport {
            cases_total: cases.len(),
            cases_passed,
            results,
        }
    }
}
