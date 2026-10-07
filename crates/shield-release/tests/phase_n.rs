#![allow(clippy::expect_used, clippy::unwrap_used)]

use nexora_shield_release::{
    migrate_to_current, ApiSurface, ArtifactDigest, CompatibilityMatrix, FeedbackStatus,
    QualificationPolicy, ReleaseChannel, ReleaseVersion, MINIMUM_ANDROID_SDK,
    PUBLIC_API_CONTRACT_VERSION, STABLE_CONFIG_SCHEMA,
};
use serde_json::json;

#[test]
fn n1_api_freeze_contract_is_valid() {
    let contract: ApiSurface =
        serde_json::from_str(include_str!("../../../release/api-surface-v1.json"))
            .expect("API contract JSON");

    contract.validate().expect("frozen API contract");
    assert_eq!(contract.contract_version, PUBLIC_API_CONTRACT_VERSION);
    assert!(contract.cli_commands.contains(&"protect".to_owned()));
    assert!(contract.cli_commands.contains(&"verify".to_owned()));
}

#[test]
fn n2_schema_one_and_min_sdk_are_stable() {
    assert_eq!(STABLE_CONFIG_SCHEMA, 1);
    assert_eq!(MINIMUM_ANDROID_SDK, 24);

    let active: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/nexora-shield.schema.json"))
            .expect("active schema");
    let frozen: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/nexora-shield.schema.v1.json"
    ))
    .expect("frozen schema");

    assert_eq!(active, frozen);
    assert_eq!(active["properties"]["schema"]["const"], 1);
}

#[test]
fn n3_legacy_config_migrates_without_dropping_unrelated_sections() {
    let source = json!({
        "applicationId": "dev.nexora.sample",
        "minSdk": 24,
        "protectionProfile": "hardened",
        "dex": {"rename": true}
    });

    let migrated = migrate_to_current(source).expect("legacy migration");

    assert!(migrated.changed);
    assert_eq!(migrated.source_schema, 0);
    assert_eq!(migrated.target_schema, 1);
    assert_eq!(migrated.document["application"]["id"], "dev.nexora.sample");
    assert_eq!(migrated.document["application"]["minSdk"], 24);
    assert_eq!(migrated.document["profile"], "hardened");
    assert!(migrated.document["dex"]["rename"]
        .as_bool()
        .unwrap_or(false));
}

#[test]
fn n3_future_schema_fails_closed() {
    let source = json!({
        "schema": 2,
        "application": {"id": "dev.nexora.sample", "minSdk": 24},
        "profile": "hardened"
    });

    assert!(migrate_to_current(source).is_err());
}

#[test]
fn n6_artifact_digest_is_deterministic() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "nexora-shield-phase-n-{}-digest.bin",
        std::process::id()
    ));
    std::fs::write(&path, b"nexora-shield-release-artifact").expect("write fixture");

    let first = ArtifactDigest::from_file(&path).expect("first digest");
    let second = ArtifactDigest::from_file(&path).expect("second digest");

    assert_eq!(first.sha256, second.sha256);
    assert_eq!(first.bytes, 30);
    let _ = std::fs::remove_file(path);
}

#[test]
fn n11_compatibility_matrix_covers_supported_release_surfaces() {
    let matrix: CompatibilityMatrix =
        serde_json::from_str(include_str!("../../../release/compatibility-matrix.json"))
            .expect("compatibility JSON");

    matrix.validate().expect("compatibility matrix");
    assert!(matrix.android_abis.contains(&"arm64-v8a".to_owned()));
    assert!(matrix.android_abis.contains(&"x86_64".to_owned()));
    assert!(matrix.artifact_types.contains(&"aab".to_owned()));
    assert!(matrix
        .desktop_operating_systems
        .contains(&"windows".to_owned()));
}

#[test]
fn n12_rc_version_is_explicit_and_stable_version_is_separate() {
    let rc = ReleaseVersion::parse("1.0.0-rc.1").expect("RC version");
    rc.require_1_0_channel(ReleaseChannel::Rc)
        .expect("RC channel");

    let stable = ReleaseVersion::parse("v1.0.0").expect("stable version");
    stable
        .require_1_0_channel(ReleaseChannel::Stable)
        .expect("stable channel");

    assert!(rc.require_1_0_channel(ReleaseChannel::Stable).is_err());
}

#[test]
fn n13_n14_stable_requires_independent_external_assessment() {
    let policy: QualificationPolicy =
        serde_json::from_str(include_str!("../../../release/qualification-policy.json"))
            .expect("qualification policy");
    policy.validate().expect("qualification policy");

    let current: FeedbackStatus =
        serde_json::from_str(include_str!("../../../release/feedback-status.json"))
            .expect("feedback status");
    assert!(policy.stable_feedback_satisfied(&current));

    let blocked = FeedbackStatus {
        schema: 1,
        external_assessments: 0,
        human_reviewers: 0,
        accepted_feedback_items: 0,
        blocking_findings_open: 0,
        assessment_providers: Vec::new(),
    };
    assert!(!policy.stable_feedback_satisfied(&blocked));
}

#[test]
fn qualification_policy_requires_stable_to_include_all_rc_gates() {
    let policy: QualificationPolicy =
        serde_json::from_str(include_str!("../../../release/qualification-policy.json"))
            .expect("qualification policy");
    policy.validate().expect("qualification policy");
    for gate in &policy.required_rc_gates {
        assert!(policy.required_stable_gates.contains(gate));
    }
}
