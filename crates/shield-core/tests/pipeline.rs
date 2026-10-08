#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use nexora_shield_core::{protect_apk, PipelineStage, ProtectionProfile, ProtectionRequest};
use std::fs::{self, File};
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn unsigned_no_align_pipeline_is_transactional_and_reports_are_written() {
    let directory = test_directory("pipeline");
    let input = directory.join("input.apk");
    let output = directory.join("protected.apk");
    let public_report = directory.join("reports/public.json");
    let private_report = directory.join("private/build.json");

    write_stored_zip(
        &input,
        &[
            ("classes.dex", b"dex-one"),
            (
                "AndroidManifest.xml",
                b"<manifest package=\"dev.nexora.test\"/>",
            ),
        ],
    );

    let request = ProtectionRequest {
        input: input.clone(),
        output: output.clone(),
        profile: ProtectionProfile::Hardened,
        align: false,
        allow_unsigned: true,
        overwrite: false,
        signing: None,
        zipalign: None,
        apksigner: None,
        public_report: Some(public_report.clone()),
        private_report: Some(private_report.clone()),
    };

    let result = protect_apk(&request).expect("Phase A pipeline");
    assert!(output.is_file());
    assert!(public_report.is_file());
    assert!(private_report.is_file());
    assert_eq!(result.output_inspection.dex_files.len(), 1);
    assert_eq!(result.stages.last(), Some(&PipelineStage::Published));
    assert!(!result.aligned);
    assert!(!result.signed);

    let public = fs::read_to_string(&public_report).expect("read public report");
    assert!(public.contains(&result.plan.build_id));
    assert!(public.contains("\"signed\": false"));
    assert!(public.contains("\"published\""));

    let second = protect_apk(&request);
    assert!(second.is_err());

    let overwrite_request = ProtectionRequest {
        overwrite: true,
        ..request
    };
    protect_apk(&overwrite_request).expect("transactional overwrite");

    cleanup(&directory);
}

#[test]
fn report_destinations_cannot_clobber_source_or_output() {
    let directory = test_directory("report-alias");
    let input = directory.join("input.apk");
    let output = directory.join("output.apk");
    write_stored_zip(
        &input,
        &[
            ("classes.dex", b"dex-one"),
            ("AndroidManifest.xml", b"<manifest/>"),
        ],
    );
    let before = fs::read(&input).expect("read source");
    let base = ProtectionRequest {
        input: input.clone(),
        output: output.clone(),
        profile: ProtectionProfile::Standard,
        align: false,
        allow_unsigned: true,
        overwrite: false,
        signing: None,
        zipalign: None,
        apksigner: None,
        public_report: None,
        private_report: None,
    };
    let source_collision = ProtectionRequest {
        public_report: Some(directory.join(".").join("input.apk")),
        ..base.clone()
    };
    assert!(protect_apk(&source_collision).is_err());
    assert_eq!(fs::read(&input).expect("source unchanged"), before);
    assert!(!output.exists());

    let output_collision = ProtectionRequest {
        private_report: Some(directory.join(".").join("output.apk")),
        ..base
    };
    assert!(protect_apk(&output_collision).is_err());
    assert!(!output.exists());
    cleanup(&directory);
}

#[test]
fn dex_staging_refuses_aliases_of_source_and_planned_output() {
    let directory = test_directory("dex-stage-alias");
    let input = directory.join("input.apk");
    let output = directory.join("output.apk");
    write_stored_zip(
        &input,
        &[
            ("AndroidManifest.xml", b"<manifest/>"),
            ("classes.dex", b"some bytes"),
        ],
    );
    let request = ProtectionRequest {
        input: input.clone(),
        output: output.clone(),
        profile: ProtectionProfile::Standard,
        align: false,
        allow_unsigned: true,
        overwrite: false,
        signing: None,
        zipalign: None,
        apksigner: None,
        public_report: None,
        private_report: None,
    };
    let context = nexora_shield_core::ProductionBuildContext::prepare(&request)
        .expect("read-only production plan");
    let config = nexora_shield_dex::MultiDexRewriteConfig {
        strip_metadata: true,
        ..Default::default()
    };
    let source_alias = directory.join(".").join("input.apk");
    let output_alias = directory.join(".").join("output.apk");
    assert!(context.stage_dex_rewrite(&source_alias, &config).is_err());
    assert!(context.stage_dex_rewrite(&output_alias, &config).is_err());
    assert!(!output.exists());
    cleanup(&directory);
}

fn test_directory(label: &str) -> PathBuf {
    let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "nexora-shield-core-phase-a-{}-{label}-{counter}",
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
        let size = u32::try_from(data.len()).expect("fixture size");
        let name_len = u16::try_from(name.len()).expect("fixture name");

        write_u32(&mut file, 0x0403_4b50);
        write_u16(&mut file, 20);
        write_u16(&mut file, 0);
        write_u16(&mut file, 0);
        write_u16(&mut file, 0);
        write_u16(&mut file, 0x0021);
        write_u32(&mut file, crc);
        write_u32(&mut file, size);
        write_u32(&mut file, size);
        write_u16(&mut file, name_len);
        write_u16(&mut file, 0);
        file.write_all(name.as_bytes()).expect("write name");
        file.write_all(data).expect("write payload");

        central.push((
            (*name).to_owned(),
            size,
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
        write_u32(&mut file, *size);
        write_u32(&mut file, *size);
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
    let central_size = u32::try_from(central_end - central_offset).expect("central size");
    let central_offset = u32::try_from(central_offset).expect("central offset");
    let count = u16::try_from(central.len()).expect("entry count");

    write_u32(&mut file, 0x0605_4b50);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u16(&mut file, count);
    write_u16(&mut file, count);
    write_u32(&mut file, central_size);
    write_u32(&mut file, central_offset);
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
