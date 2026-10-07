use nexora_shield_rasp::{
    CompiledPolicy, DebugEvaluator, DebugObservation, EmulatorEvaluator, EmulatorObservation,
    FalsePositiveCase, FalsePositiveLab, ModifiedSystemEvaluator, ModifiedSystemObservation,
    PolicyError, PolicyMode, PolicySpec, RaspResponse, ResponseEngine, RiskEngine, RiskLevel,
    SignalSet,
};

#[test]
fn report_only_mode_never_enforces_a_blocking_response() -> Result<(), PolicyError> {
    let spec = PolicySpec {
        mode: PolicyMode::ReportOnly,
        ..PolicySpec::default()
    };
    let policy = CompiledPolicy::compile(spec)?;

    let signals = DebugEvaluator::evaluate(&DebugObservation {
        tracer_pid: Some(404),
        ..DebugObservation::default()
    });
    let assessment = RiskEngine::new(policy.thresholds()).evaluate(&signals);
    let decision = ResponseEngine::decide(&policy, &assessment);

    assert_eq!(assessment.level, RiskLevel::Critical);
    assert_eq!(
        decision.configured_response,
        RaspResponse::DenySensitiveOperation
    );
    assert_eq!(decision.effective_response, RaspResponse::Report);
    assert_eq!(decision.policy_mode, PolicyMode::ReportOnly);
    Ok(())
}

#[test]
fn false_positive_matrix_passes_expected_benign_profiles() -> Result<(), PolicyError> {
    let policy = CompiledPolicy::compile(PolicySpec::default())?;

    let debug_build = DebugEvaluator::evaluate(&DebugObservation {
        application_debuggable: true,
        ..DebugObservation::default()
    });
    let weak_emulator = EmulatorEvaluator::evaluate(&EmulatorObservation {
        generic_build_profile: true,
        sparse_sensor_profile: true,
        missing_telephony_profile: true,
        ..EmulatorObservation::default()
    });
    let unlocked_bootloader = ModifiedSystemEvaluator::evaluate(&ModifiedSystemObservation {
        bootloader_unlocked: true,
        ..ModifiedSystemObservation::default()
    });
    let root_artifacts = ModifiedSystemEvaluator::evaluate(&ModifiedSystemObservation {
        root_management_artifact_count: 1,
        privileged_binary_artifact_count: 1,
        ..ModifiedSystemObservation::default()
    });
    let qemu_only = EmulatorEvaluator::evaluate(&EmulatorObservation {
        qemu_transport_present: true,
        ..EmulatorObservation::default()
    });

    let cases = vec![
        FalsePositiveCase {
            name: "clean-production".into(),
            signals: SignalSet::default(),
            maximum_risk: RiskLevel::Clean,
            maximum_response: RaspResponse::Continue,
        },
        FalsePositiveCase {
            name: "debuggable-build-only".into(),
            signals: debug_build,
            maximum_risk: RiskLevel::Clean,
            maximum_response: RaspResponse::Continue,
        },
        FalsePositiveCase {
            name: "weak-emulator-hints".into(),
            signals: weak_emulator,
            maximum_risk: RiskLevel::Observed,
            maximum_response: RaspResponse::Continue,
        },
        FalsePositiveCase {
            name: "unlocked-bootloader-only".into(),
            signals: unlocked_bootloader,
            maximum_risk: RiskLevel::Observed,
            maximum_response: RaspResponse::Continue,
        },
        FalsePositiveCase {
            name: "root-artifacts-without-strong-runtime-evidence".into(),
            signals: root_artifacts,
            maximum_risk: RiskLevel::Elevated,
            maximum_response: RaspResponse::Report,
        },
        FalsePositiveCase {
            name: "qemu-transport-only".into(),
            signals: qemu_only,
            maximum_risk: RiskLevel::Elevated,
            maximum_response: RaspResponse::Report,
        },
    ];

    let report = FalsePositiveLab::run(&policy, &cases);
    assert_eq!(report.cases_total, 6);
    assert_eq!(report.cases_passed, 6);
    assert_eq!(report.failures.len(), 0);
    Ok(())
}

#[test]
fn false_positive_lab_reports_expectation_regressions() -> Result<(), PolicyError> {
    let policy = CompiledPolicy::compile(PolicySpec::default())?;
    let signals = DebugEvaluator::evaluate(&DebugObservation {
        tracer_pid: Some(77),
        ..DebugObservation::default()
    });
    let cases = vec![FalsePositiveCase {
        name: "intentional-regression-probe".into(),
        signals,
        maximum_risk: RiskLevel::Observed,
        maximum_response: RaspResponse::Continue,
    }];

    let report = FalsePositiveLab::run(&policy, &cases);
    assert_eq!(report.cases_total, 1);
    assert_eq!(report.cases_passed, 0);
    assert_eq!(report.failures.len(), 1);
    Ok(())
}
