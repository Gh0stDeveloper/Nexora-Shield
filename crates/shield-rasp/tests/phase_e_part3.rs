use nexora_shield_rasp::{
    CompiledPolicy, DebugEvaluator, DebugObservation, EmulatorEvaluator, EmulatorObservation,
    HookInjectionEvaluator, HookInjectionObservation, PolicyError, PolicySpec, RaspResponse,
    ResponseEngine, RiskEngine, RiskLevel, RiskThresholds, SignalSet,
};

#[test]
fn empty_evidence_is_clean() {
    let assessment = RiskEngine::default().evaluate(&SignalSet::default());
    assert_eq!(assessment.score, 0);
    assert_eq!(assessment.level, RiskLevel::Clean);
}

#[test]
fn weak_emulator_hints_cannot_escalate_above_observed() {
    let signals = EmulatorEvaluator::evaluate(&EmulatorObservation {
        generic_build_profile: true,
        sparse_sensor_profile: true,
        missing_telephony_profile: true,
        ..EmulatorObservation::default()
    });

    let assessment = RiskEngine::default().evaluate(&signals);
    assert_eq!(assessment.level, RiskLevel::Observed);
}

#[test]
fn cross_category_strong_evidence_increases_risk() {
    let mut signals = DebugEvaluator::evaluate(&DebugObservation {
        debugger_connected: true,
        ..DebugObservation::default()
    });
    signals.extend(
        HookInjectionEvaluator::evaluate(&HookInjectionObservation {
            writable_executable_mapping: true,
            ..HookInjectionObservation::default()
        })
        .signals()
        .iter()
        .cloned(),
    );

    let assessment = RiskEngine::default().evaluate(&signals);
    assert_eq!(assessment.level, RiskLevel::High);
    assert!(assessment.score >= 45);
}

#[test]
fn critical_definitive_evidence_is_critical_without_extra_signals() {
    let signals = DebugEvaluator::evaluate(&DebugObservation {
        tracer_pid: Some(42),
        ..DebugObservation::default()
    });

    let assessment = RiskEngine::default().evaluate(&signals);
    assert_eq!(assessment.level, RiskLevel::Critical);
}

#[test]
fn default_policy_is_monotonic_and_non_destructive() {
    let policy = CompiledPolicy::compile(PolicySpec::default()).expect("default policy");
    assert_eq!(policy.response_for(RiskLevel::Clean), RaspResponse::Continue);
    assert_eq!(
        policy.response_for(RiskLevel::Elevated),
        RaspResponse::Report
    );
    assert_eq!(
        policy.response_for(RiskLevel::Critical),
        RaspResponse::DenySensitiveOperation
    );
}

#[test]
fn invalid_threshold_order_is_rejected() {
    let mut spec = PolicySpec::default();
    spec.thresholds = RiskThresholds {
        elevated: 50,
        high: 40,
        critical: 80,
    };

    assert_eq!(
        CompiledPolicy::compile(spec),
        Err(PolicyError::InvalidThresholdOrder)
    );
}

#[test]
fn less_restrictive_high_risk_response_is_rejected() {
    let mut spec = PolicySpec::default();
    spec.responses
        .insert(RiskLevel::Elevated, RaspResponse::RequireReverification);
    spec.responses.insert(RiskLevel::High, RaspResponse::Report);

    assert!(matches!(
        CompiledPolicy::compile(spec),
        Err(PolicyError::NonMonotonicResponse { .. })
    ));
}

#[test]
fn response_engine_applies_compiled_policy() {
    let policy = CompiledPolicy::compile(PolicySpec::default()).expect("default policy");
    let signals = DebugEvaluator::evaluate(&DebugObservation {
        tracer_pid: Some(77),
        ..DebugObservation::default()
    });
    let assessment = RiskEngine::new(policy.thresholds()).evaluate(&signals);
    let decision = ResponseEngine::decide(&policy, &assessment);

    assert_eq!(decision.risk_level, RiskLevel::Critical);
    assert_eq!(decision.response, RaspResponse::DenySensitiveOperation);
}
