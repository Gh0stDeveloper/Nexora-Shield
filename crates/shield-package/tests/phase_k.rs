#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use nexora_shield_package::{
    inspect_aab, inspect_aar, verify_aab_structure, verify_aar_structure,
    verify_apk_set_structure, AarMarker, SplitApkKind,
};
use std::fs::{self, File};
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn k1_aab_model_discovers_base_dynamic_features_resources_and_profiles() {
    let directory = test_directory("aab-model");
    let bundle = directory.join("sample.aab");

    write_stored_zip(
        &bundle,
        &[
            ("BundleConfig.pb", b"config"),
            ("base/manifest/AndroidManifest.xml", b"base-manifest"),
            ("base/dex/classes.dex", b"dex-1"),
            ("base/dex/classes2.dex", b"dex-2"),
            ("base/resources.pb", b"resources"),
            ("base/res/layout/main.xml", b"layout"),
            ("base/assets/dexopt/baseline.prof", b"profile"),
            ("base/assets/dexopt/baseline.profm", b"profile-metadata"),
            ("base/lib/arm64-v8a/libsample.so", b"native"),
            (
                "payments/manifest/AndroidManifest.xml",
                b"feature-manifest",
            ),
            ("payments/dex/classes.dex", b"feature-dex"),
            ("payments/resources.pb", b"feature-resources"),
            ("payments/res/layout/payment.xml", b"feature-layout"),
            ("BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map", b"map"),
        ],
    );

    let inspection = verify_aab_structure(&bundle).expect("valid AAB fixture");
    assert!(inspection.bundle_config_present);
    assert_eq!(inspection.modules.len(), 2);
    assert_eq!(inspection.dynamic_features, vec!["payments"]);
    assert_eq!(inspection.bundle_metadata_entries, 1);

    let base = inspection
        .modules
        .iter()
        .find(|module| module.name == "base")
        .expect("base module");
    assert_eq!(base.dex_files.len(), 2);
    assert!(base.dex_sequence_contiguous);
    assert!(base.resources_table_present);
    assert_eq!(base.resource_entries, 1);
    assert!(base.native_abis.contains("arm64-v8a"));
    assert!(base.baseline_profile.binary_present);
    assert!(base.baseline_profile.metadata_present);

    cleanup(&directory);
}

#[test]
fn k1_aab_verifier_rejects_missing_bundle_config_and_dex_gaps() {
    let directory = test_directory("aab-invalid");
    let no_config = directory.join("no-config.aab");
    write_stored_zip(
        &no_config,
        &[("base/manifest/AndroidManifest.xml", b"base-manifest")],
    );
    assert!(verify_aab_structure(&no_config).is_err());

    let dex_gap = directory.join("dex-gap.aab");
    write_stored_zip(
        &dex_gap,
        &[
            ("BundleConfig.pb", b"config"),
            ("base/manifest/AndroidManifest.xml", b"base-manifest"),
            ("base/dex/classes.dex", b"dex-1"),
            ("base/dex/classes3.dex", b"dex-3"),
        ],
    );
    let inspection = inspect_aab(&dex_gap).expect("inspect invalid AAB");
    assert!(!inspection.modules[0].dex_sequence_contiguous);
    assert!(verify_aab_structure(&dex_gap).is_err());

    cleanup(&directory);
}

#[test]
fn k4_apk_set_model_distinguishes_splits_standalones_and_universal() {
    let directory = test_directory("apk-set");
    let apks = directory.join("sample.apks");

    write_stored_zip(
        &apks,
        &[
            ("toc.pb", b"toc"),
            ("splits/base-master.apk", b"base"),
            ("splits/base-en.apk", b"language"),
            ("splits/payments-master.apk", b"feature"),
            ("standalones/standalone-arm64_v8a.apk", b"standalone"),
            ("universal.apk", b"universal"),
        ],
    );

    let inspection = verify_apk_set_structure(&apks).expect("valid APK Set");
    assert_eq!(inspection.apks.len(), 5);
    assert!(inspection
        .apks
        .iter()
        .any(|apk| apk.kind == SplitApkKind::Split));
    assert!(inspection
        .apks
        .iter()
        .any(|apk| apk.kind == SplitApkKind::Standalone));
    assert!(inspection
        .apks
        .iter()
        .any(|apk| apk.kind == SplitApkKind::Universal));

    cleanup(&directory);
}

#[test]
fn k6_k8_k9_aar_model_preserves_rules_resources_namespace_and_profiles() {
    let directory = test_directory("aar");
    let aar = directory.join("library.aar");

    write_stored_zip(
        &aar,
        &[
            ("AndroidManifest.xml", b"manifest"),
            ("classes.jar", b"jar"),
            ("R.txt", b"int string library_name 0x7f010001"),
            ("res/values/strings.xml", b"resources"),
            ("assets/data.bin", b"asset"),
            ("jni/arm64-v8a/liblibrary.so", b"native"),
            ("proguard.txt", b"-keep class dev.nexora.library.PublicApi { *; }"),
            ("baseline-prof.txt", b"Ldev/nexora/library/PublicApi;"),
            (
                "META-INF/com/android/build/gradle/aar-metadata.properties",
                b"aarFormatVersion=1.0",
            ),
        ],
    );

    let inspection = verify_aar_structure(&aar).expect("valid AAR");
    assert!(inspection.has_marker(AarMarker::Manifest));
    assert!(inspection.has_marker(AarMarker::ClassesJar));
    assert!(inspection.has_marker(AarMarker::AarMetadata));
    assert_eq!(inspection.consumer_rule_entries, vec!["proguard.txt"]);
    assert_eq!(inspection.resource_entries, 1);
    assert!(inspection.has_marker(AarMarker::ResourceSymbols));
    assert!(inspection.jni_abis.contains("arm64-v8a"));
    assert_eq!(inspection.baseline_profile_entries, vec!["baseline-prof.txt"]);

    cleanup(&directory);
}

#[test]
fn k6_aar_verifier_rejects_missing_classes_jar() {
    let directory = test_directory("aar-no-classes");
    let aar = directory.join("invalid.aar");
    write_stored_zip(&aar, &[("AndroidManifest.xml", b"manifest")]);

    let inspection = inspect_aar(&aar).expect("inspect invalid AAR");
    assert!(!inspection.has_marker(AarMarker::ClassesJar));
    assert!(verify_aar_structure(&aar).is_err());

    cleanup(&directory);
}

fn test_directory(label: &str) -> PathBuf {
    let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "nexora-shield-phase-k-{}-{label}-{counter}",
        std::process::id()
    ));
    if path.exists() {
        fs::remove_dir_all(&path).expect("remove stale test directory");
    }
    fs::create_dir_all(&path).expect("create test directory");
    path
}

fn cleanup(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

fn write_stored_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let mut file = File::create(path).expect("create ZIP fixture");
    let mut central = Vec::new();

    for (name, data) in entries {
        let offset = file.stream_position().expect("local offset");
        let crc = crc32(data);

        write_u32(&mut file, 0x0403_4b50);
        write_u16(&mut file, 20);
        write_u16(&mut file, 0);
        write_u16(&mut file, 0);
        write_u16(&mut file, 0);
        write_u16(&mut file, 0x0021);
        write_u32(&mut file, crc);
        write_u32(&mut file, u32::try_from(data.len()).expect("fixture size"));
        write_u32(&mut file, u32::try_from(data.len()).expect("fixture size"));
        write_u16(&mut file, u16::try_from(name.len()).expect("fixture name"));
        write_u16(&mut file, 0);
        file.write_all(name.as_bytes()).expect("write local name");
        file.write_all(data).expect("write local payload");

        central.push((
            (*name).to_owned(),
            data.len(),
            crc,
            u32::try_from(offset).expect("fixture offset"),
        ));
    }

    let central_offset = file.stream_position().expect("central offset");
    for (name, size, crc, offset) in &central {
        write_u32(&mut file, 0x0201_4b50);
        write_u16(&mut file, 20);
        write_u16(&mut file, 20);
        write_u16(&mut file, 0);
        write_u16(&mut file, 0);
        write_u16(&mut file, 0);
        write_u16(&mut file, 0x0021);
        write_u32(&mut file, *crc);
        write_u32(&mut file, u32::try_from(*size).expect("fixture size"));
        write_u32(&mut file, u32::try_from(*size).expect("fixture size"));
        write_u16(&mut file, u16::try_from(name.len()).expect("fixture name"));
        write_u16(&mut file, 0);
        write_u16(&mut file, 0);
        write_u16(&mut file, 0);
        write_u16(&mut file, 0);
        write_u32(&mut file, 0);
        write_u32(&mut file, *offset);
        file.write_all(name.as_bytes()).expect("write central name");
    }

    let central_end = file.stream_position().expect("central end");
    let central_size = central_end - central_offset;
    let count = u16::try_from(central.len()).expect("fixture count");

    write_u32(&mut file, 0x0605_4b50);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u16(&mut file, count);
    write_u16(&mut file, count);
    write_u32(
        &mut file,
        u32::try_from(central_size).expect("fixture central size"),
    );
    write_u32(
        &mut file,
        u32::try_from(central_offset).expect("fixture central offset"),
    );
    write_u16(&mut file, 0);
    file.flush().expect("flush fixture");
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn write_u16(file: &mut File, value: u16) {
    file.write_all(&value.to_le_bytes()).expect("write u16");
}

fn write_u32(file: &mut File, value: u32) {
    file.write_all(&value.to_le_bytes()).expect("write u32");
}
