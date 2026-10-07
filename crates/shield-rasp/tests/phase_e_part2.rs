use nexora_shield_integrity::{
    IntegrityFailure, IntegrityFailureKind, IntegrityResponse, IntegritySeverity, IntegrityVerdict,
    Sha256Digest,
};
use nexora_shield_rasp::{
    EmulatorEvaluator, EmulatorObservation, IntegritySignalFusion, ModifiedSystemEvaluator,
    ModifiedSystemObservation, SignalCategory, SignalSeverity,
};

#[test]
fn modified_system_signals_keep_independent_causes() {
    let observation = ModifiedSystemObservation {
        bootloader_unlocked: true,
        verified_boot_not_green: true,
        selinux_permissive: true,
        system_partition_writable: true,
        root_management_artifact_count: 2,
        privileged_binary_artifact_count: 1,
    };

    let signals = ModifiedSystemEvaluator::evaluate(&observation);
    assert_eq!(signals.len(), 6);
    assert_eq!(signals.maximum_severity(), SignalSeverity::High);
    assert!(signals
        .categories()
        .contains(&SignalCategory::ModifiedSystem));
}

#[test]
fn clean_modified_system_observation_is_silent() {
    assert!(ModifiedSystemEvaluator::evaluate(&ModifiedSystemObservation::default()).is_empty());
}

#[test]
fn emulator_evidence_keeps_weak_signals_weak() {
    let observation = EmulatorObservation {
        generic_build_profile: true,
        sparse_sensor_profile: true,
        missing_telephony_profile: true,
        ..EmulatorObservation::default()
    };

    let signals = EmulatorEvaluator::evaluate(&observation);
    assert_eq!(signals.len(), 3);
    assert_eq!(signals.maximum_severity(), SignalSeverity::Low);
}

#[test]
fn strong_emulator_evidence_is_reported_independently() {
    let observation = EmulatorObservation {
        qemu_transport_present: true,
        hypervisor_artifact_present: true,
        ..EmulatorObservation::default()
    };

    let signals = EmulatorEvaluator::evaluate(&observation);
    assert_eq!(signals.len(), 2);
    assert_eq!(signals.maximum_severity(), SignalSeverity::High);
}

#[test]
fn clean_emulator_observation_is_silent() {
    assert!(EmulatorEvaluator::evaluate(&EmulatorObservation::default()).is_empty());
}

#[test]
fn clean_integrity_verdict_emits_no_rasp_signal() {
    let verdict = IntegrityVerdict {
        clean: true,
        severity: IntegritySeverity::Info,
        response: IntegrityResponse::Continue,
        checks_total: 3,
        checks_passed: 3,
        failures: Vec::new(),
    };

    assert!(IntegritySignalFusion::from_verdict(&verdict).is_empty());
}

#[test]
fn integrity_failures_are_preserved_as_independent_signals() {
    let expected = Sha256Digest::of(b"expected");
    let observed = Sha256Digest::of(b"observed");
    let verdict = IntegrityVerdict {
        clean: false,
        severity: IntegritySeverity::Critical,
        response: IntegrityResponse::DenySensitiveOperation,
        checks_total: 2,
        checks_passed: 0,
        failures: vec![
            IntegrityFailure {
                node_id: Sha256Digest::of(b"certificate-node"),
                label: "signing-certificate".into(),
                kind: IntegrityFailureKind::Certificate,
                severity: IntegritySeverity::Critical,
                expected,
                observed: Some(observed),
                reason: "certificate mismatch".into(),
            },
            IntegrityFailure {
                node_id: Sha256Digest::of(b"resource-node"),
                label: "artifact:resource:assets/config.json".into(),
                kind: IntegrityFailureKind::MissingArtifact,
                severity: IntegritySeverity::High,
                expected,
                observed: None,
                reason: "artifact evidence is missing".into(),
            },
        ],
    };

    let signals = IntegritySignalFusion::from_verdict(&verdict);
    assert_eq!(signals.len(), 2);
    assert_eq!(signals.maximum_severity(), SignalSeverity::Critical);
    assert!(signals
        .signals()
        .iter()
        .any(|signal| signal.code == "integrity.certificate"));
    assert!(signals
        .signals()
        .iter()
        .any(|signal| signal.code == "integrity.missing_artifact"));
}
