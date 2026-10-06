#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use nexora_shield_crypto::{
    build_resource_bundle, inspect_container, open, protect_constant, protect_string, seal,
    unprotect_constant, BuildIdentity, CachePolicy, ConstantValue, ContainerKind, DecryptRuntime,
    ExposureBenchmark, ExposureProbe, KeyDomain, KeySchedule, PrivateDataProtectionMetadata,
    ProtectedConstantRecord, ResourceBundle, ResourceInput, ResourceSelector, Sensitivity,
    StringCandidate, StringContext, StringSensitivityModel,
};
use std::time::Duration;

fn schedule(build_id: &str) -> KeySchedule {
    let root = [0x42_u8; 32];
    KeySchedule::new(
        &root,
        BuildIdentity::new("dev.nexora.phasec", build_id).expect("identity"),
    )
    .expect("schedule")
}

#[test]
fn c1_sensitive_strings_are_classified_and_protected() {
    let schedule = schedule("build-c1");
    let model = StringSensitivityModel::default();
    let candidate = StringCandidate::new(
        "auth.client.secret",
        "client_secret=NX_SUPER_SECRET_123456789",
        StringContext::Authentication,
    );

    let decision = model.classify(&candidate);
    assert_eq!(decision.sensitivity, Sensitivity::Critical);
    assert!(model.should_protect(&decision));

    let protected = protect_string(&schedule, &model, &candidate)
        .expect("protect")
        .expect("selected");
    assert!(!contains(&protected.container, candidate.value.as_bytes()));

    let plaintext = open(
        &schedule,
        ContainerKind::String,
        &candidate.logical_id,
        &protected.container,
    )
    .expect("decrypt");
    assert_eq!(plaintext, candidate.value.as_bytes());
}

#[test]
fn c2_authenticated_container_rejects_tampering_and_wrong_identity() {
    let schedule = schedule("build-c2");
    let mut container = seal(
        &schedule,
        ContainerKind::String,
        "critical.token",
        b"NX_TOKEN_0123456789",
    )
    .expect("seal");

    let last = container.len() - 1;
    container[last] ^= 0x80;
    assert!(open(
        &schedule,
        ContainerKind::String,
        "critical.token",
        &container
    )
    .is_err());

    let intact = seal(
        &schedule,
        ContainerKind::String,
        "critical.token",
        b"NX_TOKEN_0123456789",
    )
    .expect("seal");
    assert!(open(
        &schedule,
        ContainerKind::String,
        "different.logical.id",
        &intact
    )
    .is_err());
}

#[test]
fn c3_per_build_key_derivation_changes_ids_nonces_and_ciphertext() {
    let first = schedule("build-c3-a");
    let second = schedule("build-c3-b");
    let plaintext = b"same highly sensitive value";

    let a = seal(&first, ContainerKind::String, "sensitive.value", plaintext).expect("seal first");
    let b =
        seal(&second, ContainerKind::String, "sensitive.value", plaintext).expect("seal second");

    let info_a = inspect_container(&a).expect("inspect a");
    let info_b = inspect_container(&b).expect("inspect b");
    assert_ne!(info_a.item_id, info_b.item_id);
    assert_ne!(info_a.nonce, info_b.nonce);
    assert_ne!(a, b);
    assert!(open(&second, ContainerKind::String, "sensitive.value", &a).is_err());
}

#[test]
fn nonce_changes_when_plaintext_changes_for_same_item() {
    let schedule = schedule("build-c3-content");
    let first = seal(
        &schedule,
        ContainerKind::String,
        "rotating.secret",
        b"version one",
    )
    .expect("seal one");
    let second = seal(
        &schedule,
        ContainerKind::String,
        "rotating.secret",
        b"version two",
    )
    .expect("seal two");

    assert_ne!(
        inspect_container(&first).expect("inspect one").nonce,
        inspect_container(&second).expect("inspect two").nonce
    );
}

#[test]
fn c4_runtime_decrypts_on_use_and_bounds_plaintext_cache() {
    let schedule = schedule("build-c4");
    let first = seal(
        &schedule,
        ContainerKind::String,
        "runtime.one",
        b"runtime secret one",
    )
    .expect("seal one");
    let second = seal(
        &schedule,
        ContainerKind::String,
        "runtime.two",
        b"runtime secret two",
    )
    .expect("seal two");

    let mut runtime = DecryptRuntime::new(
        schedule,
        CachePolicy::Bounded {
            max_entries: 1,
            max_bytes: 128,
            ttl: Duration::from_secs(60),
        },
    );

    let one = runtime
        .decrypt_string("runtime.one", &first)
        .expect("decrypt one");
    assert_eq!(one.as_str(), "runtime secret one");
    assert_eq!(runtime.cached_entries(), 1);

    let two = runtime
        .decrypt_string("runtime.two", &second)
        .expect("decrypt two");
    assert_eq!(two.as_str(), "runtime secret two");
    assert_eq!(runtime.cached_entries(), 1);
    assert!(runtime.cached_bytes() <= 128);

    runtime.clear();
    assert_eq!(runtime.cached_entries(), 0);
    assert_eq!(runtime.cached_bytes(), 0);
}

#[test]
fn c5_constants_round_trip_without_plaintext_encoding() {
    let schedule = schedule("build-c5");
    let values = [
        ConstantValue::Bool(true),
        ConstantValue::I32(-1337),
        ConstantValue::I64(0x1020_3040_5060_7080),
        ConstantValue::F32(3.25),
        ConstantValue::F64(-9000.125),
        ConstantValue::Bytes(b"constant secret bytes".to_vec()),
    ];

    for (index, value) in values.iter().enumerate() {
        let logical_id = format!("constant.{index}");
        let protected = protect_constant(&schedule, &logical_id, value).expect("protect constant");
        let recovered =
            unprotect_constant(&schedule, &logical_id, &protected).expect("unprotect constant");
        assert_eq!(&recovered, value);
    }
}

#[test]
fn c6_resource_selection_is_conservative() {
    let selector = ResourceSelector::default();
    assert!(
        selector
            .evaluate("assets/secure/config.json", 128)
            .expect("asset")
            .protect
    );
    assert!(
        selector
            .evaluate("res/raw/model.bin", 128)
            .expect("raw")
            .protect
    );

    for path in [
        "AndroidManifest.xml",
        "resources.arsc",
        "classes.dex",
        "lib/arm64-v8a/libapp.so",
        "res/layout/activity_main.xml",
        "META-INF/CERT.RSA",
    ] {
        assert!(!selector.evaluate(path, 128).expect("decision").protect);
    }

    assert!(selector.evaluate("../secret.bin", 128).is_err());
}

#[test]
fn c7_resource_bundle_hides_paths_and_payloads_and_round_trips() {
    let schedule = schedule("build-c7");
    let selector = ResourceSelector::default();
    let secret_path = "assets/secure/config.json";
    let secret = br#"{"endpoint":"https://private.example/api","token":"NX_RESOURCE_SECRET"}"#;

    let build = build_resource_bundle(
        &schedule,
        &selector,
        &[
            ResourceInput::new(secret_path, secret.to_vec()),
            ResourceInput::new("AndroidManifest.xml", b"<manifest/>".to_vec()),
        ],
    )
    .expect("bundle");

    assert_eq!(build.records.len(), 1);
    assert_eq!(build.skipped.len(), 1);
    assert!(!contains(&build.bytes, secret_path.as_bytes()));
    assert!(!contains(&build.bytes, secret));

    let bundle = ResourceBundle::parse(&build.bytes).expect("parse bundle");
    assert_eq!(bundle.entry_count(), 1);
    assert_eq!(
        bundle
            .decrypt(&schedule, secret_path)
            .expect("decrypt resource"),
        secret
    );
}

#[test]
fn duplicate_resource_paths_are_rejected() {
    let schedule = schedule("build-c7-dup");
    let selector = ResourceSelector::default();
    let inputs = [
        ResourceInput::new("assets/a.bin", vec![1, 2, 3]),
        ResourceInput::new("assets/a.bin", vec![4, 5, 6]),
    ];
    assert!(build_resource_bundle(&schedule, &selector, &inputs).is_err());
}

#[test]
fn c8_disabled_cache_retains_no_plaintext_entries() {
    let schedule = schedule("build-c8");
    let container = seal(
        &schedule,
        ContainerKind::String,
        "no.cache",
        b"ephemeral plaintext",
    )
    .expect("seal");
    let mut runtime = DecryptRuntime::new(schedule, CachePolicy::Disabled);
    assert_eq!(
        runtime
            .decrypt_string("no.cache", &container)
            .expect("decrypt")
            .as_str(),
        "ephemeral plaintext"
    );
    assert_eq!(runtime.cached_entries(), 0);
    assert_eq!(runtime.cached_bytes(), 0);
}

#[test]
fn c9_private_metadata_contains_mapping_but_never_key_material_or_plaintext_secret() {
    let schedule = schedule("build-c9");
    let opaque = schedule
        .opaque_item_id(KeyDomain::Constant, "constant.private")
        .expect("opaque id");

    let mut metadata = PrivateDataProtectionMetadata::new(
        schedule.identity().application_id.clone(),
        schedule.identity().build_id.clone(),
        schedule.context_fingerprint_hex(),
    );
    metadata.constants.push(ProtectedConstantRecord {
        logical_id: "constant.private".into(),
        opaque_id: nexora_shield_crypto::hex_lower(&opaque),
        original_bytes: 8,
        protected_bytes: 128,
    });

    let json = metadata.to_json_pretty().expect("json");
    assert!(!json.contains("4242424242424242"));
    assert!(!json.contains("root_secret"));
    assert!(!json.contains("content_key"));
    assert!(!json.contains("NX_SUPER_SECRET"));
    assert_eq!(
        PrivateDataProtectionMetadata::from_json(&json).expect("parse metadata"),
        metadata
    );
}

#[test]
fn c10_exposure_benchmark_proves_critical_probe_removed_with_budgeted_overhead() {
    let schedule = schedule("build-c10");
    let needle = b"NX_CRITICAL_TOKEN_0123456789";
    let mut baseline = vec![b'A'; 8 * 1024];
    baseline.extend_from_slice(needle);
    baseline.extend_from_slice(&vec![b'B'; 8 * 1024]);

    let protected = seal(
        &schedule,
        ContainerKind::Generic,
        "benchmark.payload",
        &baseline,
    )
    .expect("protect benchmark");

    let report = ExposureBenchmark::run(
        &baseline,
        &protected,
        &[ExposureProbe::new("critical-token", needle.to_vec(), true).expect("probe")],
    )
    .expect("benchmark");

    assert_eq!(report.findings[0].baseline_hits, 1);
    assert_eq!(report.findings[0].protected_hits, 0);
    assert_eq!(report.critical_exposed, 0);
    assert!(report.passes(5.0));
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
