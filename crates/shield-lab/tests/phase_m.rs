#![allow(clippy::expect_used, clippy::unwrap_used)]

use nexora_shield_diversity::{BuildDiversitySignature, DiversitySurface};
use nexora_shield_lab::{
    AuditEvidenceClass, AuditEvidenceItem, AuditPreparation, AuditReadinessInput,
    AuditRequirement, BenchmarkControl, ComparativeBenchmarkMethodology, ExposureRule, FuzzFarm, ModifiedEnvironmentCase,
    ModifiedEnvironmentLab, PerformanceBudget, PerformanceFarm, PerformanceSample, PortabilityLab,
    RegressionCorpus, RegressionCoverage, RuntimeInstrumentationCase, RuntimeInstrumentationLab, SecurityControlResult,
    SecurityScore, StaticExposureHarness, TamperKind, TamperLab, TamperObservation,
};
use nexora_shield_rasp::{
    CompiledPolicy, EmulatorObservation, HookInjectionObservation, InstrumentationObservation,
    ModifiedSystemObservation, PolicySpec, RaspResponse, RiskLevel,
};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn m1_static_exposure_harness_detects_synthetic_plaintext() {
    let rule = ExposureRule {
        id: "critical-token".into(),
        needle: "NX_TEST_SECRET_MARKER".into(),
        maximum_occurrences: 0,
    };
    let clean = StaticExposureHarness::scan(
        "protected.apk",
        b"opaque-container",
        std::slice::from_ref(&rule),
    )
        .expect("valid exposure scan");
    let exposed = StaticExposureHarness::scan(
        "unprotected.apk",
        b"prefix-NX_TEST_SECRET_MARKER-suffix",
        &[rule],
    )
    .expect("valid exposure scan");

    assert!(clean.passed());
    assert!(!exposed.passed());
    assert_eq!(exposed.findings[0].occurrences, 1);
}

#[test]
fn m2_m3_tamper_harness_requires_repack_and_resign_rejection() {
    let report = TamperLab::evaluate(&[
        TamperObservation {
            case_id: "m2.dex-repack".into(),
            kind: TamperKind::RepackedDex,
            verifier_accepted: false,
        },
        TamperObservation {
            case_id: "m2.resource-repack".into(),
            kind: TamperKind::RepackedResource,
            verifier_accepted: false,
        },
        TamperObservation {
            case_id: "m3.resign".into(),
            kind: TamperKind::ReSignedArtifact,
            verifier_accepted: false,
        },
    ]);

    assert!(report.passed());
    assert_eq!(report.cases_rejected, 3);
}

#[test]
fn m4_runtime_instrumentation_lab_uses_real_rasp_policy() {
    let policy = CompiledPolicy::compile(PolicySpec::default()).expect("default policy");
    let report = RuntimeInstrumentationLab::run(
        &policy,
        &[RuntimeInstrumentationCase {
            name: "method-dispatch-tamper".into(),
            instrumentation: InstrumentationObservation {
                method_dispatch_changed: true,
                ..InstrumentationObservation::default()
            },
            hooks: HookInjectionObservation::default(),
            minimum_risk: RiskLevel::Critical,
            minimum_response: RaspResponse::DenySensitiveOperation,
        }],
    );

    assert_eq!(report.cases_total, 1);
    assert_eq!(report.cases_passed, 1);
    assert!(report.results[0].passed);
}

#[test]
fn m5_modified_environment_matrix_correlates_independent_categories() {
    let policy = CompiledPolicy::compile(PolicySpec::default()).expect("default policy");
    let report = ModifiedEnvironmentLab::run(
        &policy,
        &[ModifiedEnvironmentCase {
            name: "modified-virtualized-device".into(),
            system: ModifiedSystemObservation {
                verified_boot_not_green: true,
                ..ModifiedSystemObservation::default()
            },
            emulator: EmulatorObservation {
                qemu_transport_present: true,
                ..EmulatorObservation::default()
            },
            minimum_risk: RiskLevel::High,
            minimum_response: RaspResponse::RequireReverification,
        }],
    );

    assert_eq!(report.cases_passed, 1);
    assert!(report.results[0].signals >= 2);
}

#[test]
fn m6_bypass_portability_gate_rejects_transferable_builds() {
    let unique = vec![
        signature(1, 11),
        signature(2, 22),
        signature(3, 33),
        signature(4, 44),
    ];
    let good = PortabilityLab::evaluate(&unique, 1_500);
    assert!(good.passed);
    assert!(good.report.all_builds_unique());

    let repeated = vec![signature(1, 11), signature(1, 12)];
    let bad = PortabilityLab::evaluate(&repeated, 1_500);
    assert!(!bad.passed);
}

#[test]
fn m7_fuzz_farm_never_allows_parser_panics() {
    let seeds = vec![
        br#"{"schema":1,"value":"alpha"}"#.to_vec(),
        br#"{"schema":1,"value":"beta"}"#.to_vec(),
    ];
    let report = FuzzFarm::run(&seeds, 64, |bytes| {
        serde_json::from_slice::<serde_json::Value>(bytes)
            .map(|_| ())
            .map_err(|error| error.to_string())
    });

    assert_eq!(report.cases_total, 128);
    assert_eq!(report.panics, 0);
    assert!(report.passed());
}

#[test]
fn m8_performance_farm_enforces_runtime_and_size_budgets() {
    let report = PerformanceFarm::evaluate(
        &[
            PerformanceSample {
                label: "startup-a".into(),
                baseline_micros: 1_000,
                protected_micros: 1_080,
                baseline_bytes: 10_000,
                protected_bytes: 10_400,
            },
            PerformanceSample {
                label: "startup-b".into(),
                baseline_micros: 1_100,
                protected_micros: 1_200,
                baseline_bytes: 10_000,
                protected_bytes: 10_500,
            },
        ],
        PerformanceBudget {
            maximum_runtime_overhead_basis_points: 1_000,
            maximum_size_overhead_basis_points: 600,
        },
    )
    .expect("valid performance report");

    assert!(report.passed);
    assert!(report.maximum_runtime_overhead_basis_points <= 1_000);
    assert!(report.maximum_size_overhead_basis_points <= 600);
}

#[test]
fn m9_regression_corpus_is_versioned_unique_and_fingerprinted() {
    let corpus: RegressionCorpus = serde_json::from_str(include_str!(
        "../../../security-lab/corpus/index.json"
    ))
    .expect("corpus JSON");

    corpus.validate().expect("valid corpus");
    assert!(corpus.cases.len() >= 12);
    assert_ne!(corpus.fingerprint().expect("fingerprint"), [0_u8; 32]);

    let coverage: RegressionCoverage = serde_json::from_str(include_str!(
        "../../../security-lab/corpus/coverage.json"
    ))
    .expect("coverage JSON");
    coverage
        .validate_against(&corpus)
        .expect("every corpus case has a release gate");
}

#[test]
fn m10_security_score_caps_grade_when_a_critical_control_fails() {
    let score = SecurityScore::calculate(&[
        SecurityControlResult {
            id: "integrity".into(),
            weight: 50,
            critical: true,
            passed: false,
        },
        SecurityControlResult {
            id: "fuzz".into(),
            weight: 25,
            critical: false,
            passed: true,
        },
        SecurityControlResult {
            id: "performance".into(),
            weight: 25,
            critical: false,
            passed: true,
        },
    ]);

    assert_eq!(score.score_basis_points, 5_000);
    assert_eq!(score.grade, "F");
    assert_eq!(score.critical_failures, vec!["integrity"]);
}

#[test]
fn m11_comparative_benchmark_methodology_is_strict_by_default() {
    let methodology = ComparativeBenchmarkMethodology::default();
    methodology.validate().expect("strict methodology");
    assert!(methodology.measured_runs >= 10);
    assert!(methodology.controls.contains(&BenchmarkControl::RetainRawSamples));
}

#[test]
fn m12_external_audit_preparation_rejects_unredacted_confidential_evidence() {
    let requirements_present = BTreeSet::from([
        AuditRequirement::ThreatModel,
        AuditRequirement::SecurityPolicy,
        AuditRequirement::PhaseChecklists,
        AuditRequirement::RegressionCorpus,
        AuditRequirement::BenchmarkMethodology,
        AuditRequirement::CiEvidence,
    ]);
    let safe = AuditPreparation::evaluate(&AuditReadinessInput {
        requirements_present: requirements_present.clone(),
        evidence: vec![AuditEvidenceItem {
            id: "public-report".into(),
            relative_path: "reports/security-lab.json".into(),
            class: AuditEvidenceClass::Public,
            redacted: false,
        }],
    })
    .expect("safe audit input");
    assert!(safe.ready);

    let unsafe_report = AuditPreparation::evaluate(&AuditReadinessInput {
        requirements_present,
        evidence: vec![AuditEvidenceItem {
            id: "private-manifest".into(),
            relative_path: "private/manifest.json".into(),
            class: AuditEvidenceClass::Confidential,
            redacted: false,
        }],
    })
    .expect("valid but unsafe audit evidence");

    assert!(!unsafe_report.ready);
    assert_eq!(unsafe_report.unsafe_evidence, vec!["private-manifest"]);
}

fn signature(surface_seed: u8, fingerprint_seed: u8) -> BuildDiversitySignature {
    let surfaces = BTreeMap::from([
        (DiversitySurface::Rename, [surface_seed; 32]),
        (DiversitySurface::PassOrder, [surface_seed.wrapping_add(1); 32]),
        (DiversitySurface::Cfg, [surface_seed.wrapping_add(2); 32]),
        (
            DiversitySurface::IntegrityTopology,
            [surface_seed.wrapping_add(3); 32],
        ),
        (
            DiversitySurface::StringPartition,
            [surface_seed.wrapping_add(4); 32],
        ),
        (DiversitySurface::VmMap, [surface_seed.wrapping_add(5); 32]),
        (
            DiversitySurface::NativeConstants,
            [surface_seed.wrapping_add(6); 32],
        ),
    ]);
    BuildDiversitySignature {
        surfaces,
        full_fingerprint: [fingerprint_seed; 32],
    }
}
