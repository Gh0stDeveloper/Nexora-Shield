#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use nexora_shield_dex::{refresh_integrity, DEX_ENDIAN_CONSTANT, DEX_HEADER_SIZE};
use nexora_shield_integrity::{
    ArtifactIntegrity, ArtifactKind, CertificateBinding, CertificateObservation,
    CertificatePolicy, DexIntegrity, DistributionPlan, IntegrityEvidence, IntegrityManifest,
    IntegrityResponse, IntegritySeverity, IntegrityVerifier, PackageBinding, PackageObservation,
    ResponsePolicy, Sha256Digest, DEFAULT_DEX_CHUNK_BYTES,
};
use std::collections::BTreeMap;

fn signer_a() -> Sha256Digest {
    Sha256Digest::of(b"phase-d-signer-a")
}

fn signer_b() -> Sha256Digest {
    Sha256Digest::of(b"phase-d-signer-b")
}

fn manifest_and_evidence() -> (IntegrityManifest, IntegrityEvidence) {
    let certificate =
        CertificateBinding::new(CertificatePolicy::ExactCurrent, [signer_a()], [])
            .expect("certificate binding");
    let package =
        PackageBinding::new("dev.nexora.integrity", 42, None).expect("package binding");

    let dex_bytes = build_test_dex("Ldev/nexora/integrity/Main;", "run");
    let dex = DexIntegrity::build("classes.dex", &dex_bytes, DEFAULT_DEX_CHUNK_BYTES)
        .expect("DEX integrity");

    let resource_bytes = br#"{"endpoint":"https://example.invalid/api"}"#.to_vec();
    let native_bytes = b"ELFphase-d-native-fixture".to_vec();
    let resource = ArtifactIntegrity::build(
        "assets/config.json",
        ArtifactKind::Resource,
        &resource_bytes,
    )
    .expect("resource integrity");
    let native = ArtifactIntegrity::build(
        "lib/arm64-v8a/libnexora.so",
        ArtifactKind::Native,
        &native_bytes,
    )
    .expect("native integrity");

    let manifest = IntegrityManifest::build(
        "phase-d-build",
        certificate,
        package,
        vec![dex],
        vec![resource, native],
        b"phase-d-distribution-seed",
        5,
        2,
        ResponsePolicy::default(),
    )
    .expect("integrity manifest");

    let certificate =
        CertificateObservation::new([signer_a()], []).expect("certificate observation");
    let package =
        PackageObservation::new("dev.nexora.integrity", 42, None).expect("package observation");
    let dex_files = BTreeMap::from([("classes.dex".to_owned(), dex_bytes)]);
    let artifacts = BTreeMap::from([
        ("assets/config.json".to_owned(), resource_bytes),
        ("lib/arm64-v8a/libnexora.so".to_owned(), native_bytes),
    ]);

    (
        manifest,
        IntegrityEvidence {
            certificate,
            package,
            dex_files,
            artifacts,
        },
    )
}

#[test]
fn d1_certificate_binding_detects_resign_and_accepts_configured_lineage() {
    let exact = CertificateBinding::new(
        CertificatePolicy::ExactCurrent,
        [signer_a()],
        [],
    )
    .expect("exact binding");
    let original =
        CertificateObservation::new([signer_a()], []).expect("original observation");
    let resigned =
        CertificateObservation::new([signer_b()], []).expect("resigned observation");

    assert!(exact.verify(&original).matched);
    assert!(!exact.verify(&resigned).matched);

    let lineage = CertificateBinding::new(
        CertificatePolicy::CurrentOrLineage,
        [signer_a()],
        [],
    )
    .expect("lineage binding");
    let rotated = CertificateObservation::new([signer_b()], [signer_a()])
        .expect("rotated observation");
    assert!(lineage.verify(&rotated).matched);
}

#[test]
fn d2_package_binding_is_exact_for_name_version_and_split() {
    let binding = PackageBinding::new("dev.nexora.integrity", 42, None)
        .expect("package binding");
    let same = PackageObservation::new("dev.nexora.integrity", 42, None)
        .expect("same package");
    let wrong_version = PackageObservation::new("dev.nexora.integrity", 43, None)
        .expect("wrong version");
    let wrong_package = PackageObservation::new("dev.other.app", 42, None)
        .expect("wrong package");

    assert!(binding.verify(&same).matched);
    assert!(!binding.verify(&wrong_version).matched);
    assert!(!binding.verify(&wrong_package).matched);
}

#[test]
fn d3_dex_regions_detect_local_patch_without_relying_on_one_digest() {
    let bytes = build_test_dex("Ldev/nexora/integrity/Main;", "run");
    let integrity = DexIntegrity::build("classes.dex", &bytes, 32)
        .expect("DEX integrity");
    assert!(integrity.regions.len() >= 4);

    let clean = integrity.verify(&bytes).expect("clean verification");
    assert!(clean.iter().all(|check| check.matched));

    let mut patched = bytes.clone();
    let index = patched.len() - 1;
    patched[index] ^= 0x01;
    let checks = integrity.verify(&patched).expect("patched verification");
    assert!(checks.iter().any(|check| !check.matched));
    assert!(checks
        .iter()
        .filter(|check| check.label.starts_with("data:"))
        .any(|check| !check.matched));
}

#[test]
fn d4_resource_integrity_detects_content_replacement() {
    let expected = ArtifactIntegrity::build(
        "assets/config.json",
        ArtifactKind::Resource,
        b"trusted-resource",
    )
    .expect("resource");
    assert!(expected
        .verify(b"trusted-resource")
        .expect("verify clean")
        .matched);
    assert!(!expected
        .verify(b"patched-resource")
        .expect("verify patch")
        .matched);
}

#[test]
fn d5_native_integrity_detects_library_replacement() {
    let expected = ArtifactIntegrity::build(
        "lib/arm64-v8a/libnexora.so",
        ArtifactKind::Native,
        b"ELForiginal-native",
    )
    .expect("native");
    assert!(expected
        .verify(b"ELForiginal-native")
        .expect("verify clean")
        .matched);
    assert!(!expected
        .verify(b"ELFpatched-native")
        .expect("verify patch")
        .matched);
}

#[test]
fn d6_integrity_graph_is_certificate_rooted_and_manifest_is_self_consistent() {
    let (manifest, _) = manifest_and_evidence();
    manifest.validate().expect("manifest valid");
    assert_eq!(
        manifest.graph.nodes.first().is_some(),
        true,
        "graph contains nodes"
    );

    let json = manifest.to_json_pretty().expect("manifest JSON");
    let round_trip = IntegrityManifest::from_json(&json).expect("manifest parse");
    assert_eq!(round_trip, manifest);

    let mut value: serde_json::Value = serde_json::from_str(&json).expect("JSON value");
    value["artifacts"][0]["digest"] =
        serde_json::Value::String(Sha256Digest::of(b"forged").to_string());
    let tampered = serde_json::to_string(&value).expect("tampered JSON");
    assert!(IntegrityManifest::from_json(&tampered).is_err());
}

#[test]
fn d7_distributed_checks_cover_each_node_with_configured_redundancy() {
    let (manifest, _) = manifest_and_evidence();
    manifest
        .distribution
        .validate(&manifest.graph)
        .expect("distribution valid");

    let different = DistributionPlan::compile(
        &manifest.graph,
        b"different-distribution-seed",
        5,
        2,
    )
    .expect("different plan");

    assert_ne!(
        manifest.distribution.seed_fingerprint,
        different.seed_fingerprint
    );
    assert_ne!(manifest.distribution.checks, different.checks);

    for check in &manifest.distribution.checks {
        assert!(manifest
            .distribution
            .nodes_for_check(check.check_id)
            .is_some());
    }
}

#[test]
fn d8_response_api_denies_sensitive_operation_for_critical_tamper() {
    let (manifest, mut evidence) = manifest_and_evidence();
    let clean = IntegrityVerifier::verify_all(&manifest, &evidence)
        .expect("clean verdict");
    assert!(clean.clean);
    assert_eq!(clean.severity, IntegritySeverity::Info);
    assert_eq!(clean.response, IntegrityResponse::Continue);

    evidence
        .artifacts
        .get_mut("lib/arm64-v8a/libnexora.so")
        .expect("native evidence")
        .push(0xff);
    let tampered = IntegrityVerifier::verify_all(&manifest, &evidence)
        .expect("tampered verdict");
    assert!(!tampered.clean);
    assert_eq!(tampered.severity, IntegritySeverity::Critical);
    assert_eq!(
        tampered.response,
        IntegrityResponse::DenySensitiveOperation
    );
}

#[test]
fn d9_resign_evidence_is_critical_even_when_payload_is_unchanged() {
    let (manifest, mut evidence) = manifest_and_evidence();
    evidence.certificate =
        CertificateObservation::new([signer_b()], []).expect("new signer");

    let verdict = IntegrityVerifier::verify_all(&manifest, &evidence)
        .expect("re-sign verdict");
    assert!(!verdict.clean);
    assert_eq!(verdict.severity, IntegritySeverity::Critical);
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.label == "signing-certificate"));
}

#[test]
fn d10_patch_and_repack_variants_are_detected_and_distributed_checks_fail() {
    let (manifest, mut evidence) = manifest_and_evidence();

    evidence.package =
        PackageObservation::new("dev.nexora.repacked", 42, None)
            .expect("repacked package");
    evidence
        .dex_files
        .get_mut("classes.dex")
        .expect("DEX evidence")[20] ^= 0x40;
    evidence
        .artifacts
        .get_mut("assets/config.json")
        .expect("resource evidence")[0] ^= 0x01;

    let full = IntegrityVerifier::verify_all(&manifest, &evidence)
        .expect("full verdict");
    assert!(!full.clean);
    assert!(full.failures.len() >= 3);

    let failing_distributed = manifest
        .distribution
        .checks
        .iter()
        .filter_map(|check| {
            IntegrityVerifier::verify_check(&manifest, &evidence, check.check_id)
                .ok()
                .filter(|verdict| !verdict.clean)
        })
        .count();
    assert!(failing_distributed >= 2);
}

#[test]
fn missing_artifact_and_missing_dex_are_fail_closed() {
    let (manifest, mut evidence) = manifest_and_evidence();
    evidence.dex_files.clear();
    evidence.artifacts.clear();

    let verdict = IntegrityVerifier::verify_all(&manifest, &evidence)
        .expect("missing evidence verdict");
    assert!(!verdict.clean);
    assert_eq!(verdict.response, IntegrityResponse::DenySensitiveOperation);
    assert!(verdict.failures.len() > 2);
}

fn build_test_dex(class_descriptor: &str, method_name: &str) -> Vec<u8> {
    let strings = [
        class_descriptor,
        "Ljava/lang/Object;",
        "V",
        method_name,
        "Main.java",
    ];

    let string_ids_off = DEX_HEADER_SIZE;
    let type_ids_off = string_ids_off + len_u32(strings.len()) * 4;
    let proto_ids_off = type_ids_off + 3 * 4;
    let method_ids_off = proto_ids_off + 12;
    let class_defs_off = method_ids_off + 8;
    let data_off = class_defs_off + 32;

    let mut bytes = vec![0_u8; usize::try_from(data_off).expect("data offset fits usize")];
    let mut string_offsets = Vec::with_capacity(strings.len());

    for value in strings {
        string_offsets.push(len_u32(bytes.len()));
        write_uleb128(&mut bytes, len_u32(value.encode_utf16().count()));
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
    }

    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }

    let code_off = len_u32(bytes.len());
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 1);
    push_u16(&mut bytes, 0x000e);

    let class_data_off = len_u32(bytes.len());
    write_uleb128(&mut bytes, 0);
    write_uleb128(&mut bytes, 0);
    write_uleb128(&mut bytes, 1);
    write_uleb128(&mut bytes, 0);
    write_uleb128(&mut bytes, 0);
    write_uleb128(&mut bytes, 0x0009);
    write_uleb128(&mut bytes, code_off);

    let file_size = len_u32(bytes.len());
    bytes[0..8].copy_from_slice(b"dex\n035\0");
    put_u32(&mut bytes, 32, file_size);
    put_u32(&mut bytes, 36, DEX_HEADER_SIZE);
    put_u32(&mut bytes, 40, DEX_ENDIAN_CONSTANT);
    put_u32(&mut bytes, 44, 0);
    put_u32(&mut bytes, 48, 0);
    put_u32(&mut bytes, 52, 0);
    put_u32(&mut bytes, 56, len_u32(strings.len()));
    put_u32(&mut bytes, 60, string_ids_off);
    put_u32(&mut bytes, 64, 3);
    put_u32(&mut bytes, 68, type_ids_off);
    put_u32(&mut bytes, 72, 1);
    put_u32(&mut bytes, 76, proto_ids_off);
    put_u32(&mut bytes, 80, 0);
    put_u32(&mut bytes, 84, 0);
    put_u32(&mut bytes, 88, 1);
    put_u32(&mut bytes, 92, method_ids_off);
    put_u32(&mut bytes, 96, 1);
    put_u32(&mut bytes, 100, class_defs_off);
    put_u32(&mut bytes, 104, file_size - data_off);
    put_u32(&mut bytes, 108, data_off);

    for (index, offset) in string_offsets.iter().enumerate() {
        put_u32(
            &mut bytes,
            usize::try_from(string_ids_off).expect("string table offset") + index * 4,
            *offset,
        );
    }

    let type_base = usize::try_from(type_ids_off).expect("type table offset");
    put_u32(&mut bytes, type_base, 0);
    put_u32(&mut bytes, type_base + 4, 1);
    put_u32(&mut bytes, type_base + 8, 2);

    let proto_base = usize::try_from(proto_ids_off).expect("proto offset");
    put_u32(&mut bytes, proto_base, 2);
    put_u32(&mut bytes, proto_base + 4, 2);
    put_u32(&mut bytes, proto_base + 8, 0);

    let method_base = usize::try_from(method_ids_off).expect("method offset");
    put_u16(&mut bytes, method_base, 0);
    put_u16(&mut bytes, method_base + 2, 0);
    put_u32(&mut bytes, method_base + 4, 3);

    let class_base = usize::try_from(class_defs_off).expect("class offset");
    put_u32(&mut bytes, class_base, 0);
    put_u32(&mut bytes, class_base + 4, 1);
    put_u32(&mut bytes, class_base + 8, 1);
    put_u32(&mut bytes, class_base + 12, 0);
    put_u32(&mut bytes, class_base + 16, 4);
    put_u32(&mut bytes, class_base + 20, 0);
    put_u32(&mut bytes, class_base + 24, class_data_off);
    put_u32(&mut bytes, class_base + 28, 0);

    refresh_integrity(&mut bytes).expect("refresh DEX integrity");
    bytes
}

fn len_u32(value: usize) -> u32 {
    u32::try_from(value).expect("fixture length fits u32")
}

fn write_uleb128(output: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = u8::try_from(value & 0x7f).expect("ULEB chunk fits u8");
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
