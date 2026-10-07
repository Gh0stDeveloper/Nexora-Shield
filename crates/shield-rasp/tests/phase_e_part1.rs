use nexora_shield_rasp::{
    DebugEvaluator, DebugObservation, EvidenceStrength, HookInjectionEvaluator,
    HookInjectionObservation, InstrumentationEvaluator, InstrumentationObservation, RaspSignal,
    SignalCategory, SignalSet, SignalSeverity, SignalSource,
};

#[test]
fn signal_set_deduplicates_identical_evidence() {
    let signal = RaspSignal::new(
        "debug.debugger_connected",
        SignalCategory::Debug,
        SignalSeverity::High,
        EvidenceStrength::Strong,
        SignalSource::AndroidRuntime,
        "debugger connected",
    );

    let mut set = SignalSet::default();
    assert!(set.push(signal.clone()));
    assert!(!set.push(signal));
    assert_eq!(set.len(), 1);
}

#[test]
fn debug_evidence_is_independent_and_auditable() {
    let observation = DebugObservation {
        application_debuggable: true,
        debugger_connected: true,
        waiting_for_debugger: false,
        jdwp_transport_active: true,
        tracer_pid: Some(144),
    };

    let signals = DebugEvaluator::evaluate(&observation);
    assert_eq!(signals.len(), 4);
    assert_eq!(signals.maximum_severity(), SignalSeverity::Critical);
    assert!(signals
        .signals()
        .iter()
        .any(|signal| signal.code == "debug.tracer_present"));
}

#[test]
fn zero_tracer_pid_does_not_create_false_evidence() {
    let observation = DebugObservation {
        tracer_pid: Some(0),
        ..DebugObservation::default()
    };

    assert!(DebugEvaluator::evaluate(&observation).is_empty());
}

#[test]
fn instrumentation_evidence_keeps_distinct_causes() {
    let observation = InstrumentationObservation {
        runtime_agent_present: true,
        instrumentation_bridge_present: true,
        unexpected_class_loader: false,
        method_dispatch_changed: true,
        loaded_agent_count: 2,
    };

    let signals = InstrumentationEvaluator::evaluate(&observation);
    assert_eq!(signals.len(), 4);
    assert_eq!(signals.maximum_severity(), SignalSeverity::Critical);
    assert!(signals
        .categories()
        .contains(&SignalCategory::Instrumentation));
}

#[test]
fn hook_and_injection_evidence_is_not_collapsed_to_one_boolean() {
    let observation = HookInjectionObservation {
        inline_hook_evidence: true,
        import_table_redirect: true,
        writable_executable_mapping: true,
        code_page_hash_mismatch: true,
        injected_library_count: 1,
    };

    let signals = HookInjectionEvaluator::evaluate(&observation);
    assert_eq!(signals.len(), 5);
    assert_eq!(signals.maximum_severity(), SignalSeverity::Critical);
    assert!(signals
        .signals()
        .iter()
        .any(|signal| signal.code == "hook.writable_executable_mapping"));
}

#[test]
fn clean_observations_emit_no_suspicious_signals() {
    assert!(DebugEvaluator::evaluate(&DebugObservation::default()).is_empty());
    assert!(InstrumentationEvaluator::evaluate(&InstrumentationObservation::default()).is_empty());
    assert!(HookInjectionEvaluator::evaluate(&HookInjectionObservation::default()).is_empty());
}
