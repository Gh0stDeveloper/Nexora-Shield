#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use nexora_shield_package::{
    inspect_apk, normalize_zip, read_zip_directory, verify_apk_structure,
    verify_normalized_equivalence, ManifestFormat,
};
use std::fs::{self, File};
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn normalizer_preserves_payload_identity_and_discovers_multidex() {
    let directory = test_directory("normalize");
    let input = directory.join("input.apk");
    let output = directory.join("output.apk");

    write_stored_zip(
        &input,
        &[
            ("res/raw/data.bin", b"payload"),
            ("classes2.dex", b"dex-two"),
            ("META-INF/CERT.SF", b"stale-signature"),
            (
                "AndroidManifest.xml",
                b"<manifest package=\"dev.nexora.test\"/>",
            ),
            ("classes.dex", b"dex-one"),
            ("META-INF/CERT.RSA", b"stale-signature-block"),
            ("META-INF/MANIFEST.MF", b"stale-manifest"),
        ],
    );

    let summary = normalize_zip(&input, &output).expect("normalize test APK");
    assert_eq!(summary.input_entries, 7);
    assert_eq!(summary.output_entries, 4);
    assert_eq!(summary.stripped_signature_entries.len(), 3);

    verify_normalized_equivalence(&input, &output).expect("payload identity");
    let inspection = verify_apk_structure(&output).expect("valid normalized APK");

    assert_eq!(inspection.manifest.format, ManifestFormat::TextXml);
    assert_eq!(inspection.dex_files.len(), 2);
    assert!(inspection.dex_sequence_contiguous);
    assert_eq!(inspection.legacy_signature_entries, Vec::<String>::new());

    let zip = read_zip_directory(&output).expect("read normalized central directory");
    let names = zip
        .entries
        .iter()
        .map(|entry| entry.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "AndroidManifest.xml",
            "classes.dex",
            "classes2.dex",
            "res/raw/data.bin"
        ]
    );

    cleanup(&directory);
}

#[test]
fn equivalence_rejects_payload_tamper_even_when_crc_metadata_is_unchanged() {
    let directory = test_directory("tampered-raw-payload");
    let input = directory.join("input.apk");
    let output = directory.join("output.apk");
    write_stored_zip(
        &input,
        &[
            ("AndroidManifest.xml", b"<manifest/>"),
            ("classes.dex", b"original-dex"),
            ("res/raw/token.bin", b"payload"),
        ],
    );
    normalize_zip(&input, &output).expect("normalize fixture");
    verify_normalized_equivalence(&input, &output).expect("unmodified archive");

    let mut bytes = fs::read(&output).expect("read normalized archive");
    let needle = b"payload";
    let position = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("find stored payload");
    bytes[position..position + needle.len()].copy_from_slice(b"PAYLOAD");
    fs::write(&output, bytes).expect("write byte-tampered archive");

    // The ZIP still parses with original central CRC/size records, but the
    // stream-preservation check must reject the modified payload.
    read_zip_directory(&output).expect("unchanged ZIP directory");
    assert!(verify_normalized_equivalence(&input, &output).is_err());
    cleanup(&directory);
}

#[test]
fn verifier_rejects_non_contiguous_multidex_sequence() {
    let directory = test_directory("dex-gap");
    let input = directory.join("gap.apk");

    write_stored_zip(
        &input,
        &[
            ("AndroidManifest.xml", b"<manifest/>"),
            ("classes.dex", b"dex-one"),
            ("classes3.dex", b"dex-three"),
        ],
    );

    let inspection = inspect_apk(&input).expect("inspect APK");
    assert!(!inspection.dex_sequence_contiguous);
    assert!(verify_apk_structure(&input).is_err());

    cleanup(&directory);
}

#[test]
fn rewrite_refuses_existing_destination_without_changing_it() {
    let directory = test_directory("existing-destination");
    let input = directory.join("input.apk");
    let output = directory.join("existing.apk");
    write_stored_zip(
        &input,
        &[
            ("AndroidManifest.xml", b"<manifest/>"),
            ("classes.dex", b"original"),
        ],
    );
    fs::write(&output, b"important existing data").expect("create existing output");
    let mut replacements = std::collections::BTreeMap::new();
    replacements.insert("classes.dex".to_string(), b"rewritten".to_vec());
    let failed = nexora_shield_package::rewrite_stored_entries(&input, &output, &replacements);
    assert!(failed.is_err());
    assert_eq!(
        fs::read(&output).expect("read existing output"),
        b"important existing data"
    );
    cleanup(&directory);
}

#[test]
fn rewrite_does_not_publish_partial_archive_on_invalid_input() {
    let directory = test_directory("invalid-rewrite");
    let input = directory.join("input.apk");
    let output = directory.join("incomplete.apk");
    write_stored_zip(
        &input,
        &[
            ("AndroidManifest.xml", b"<manifest/>"),
            ("classes.dex", b"original"),
        ],
    );
    let mut replacements = std::collections::BTreeMap::new();
    replacements.insert("missing.dex".to_string(), b"rewritten".to_vec());
    assert!(nexora_shield_package::rewrite_stored_entries(&input, &output, &replacements).is_err());
    assert!(!output.exists());
    cleanup(&directory);
}

#[cfg(unix)]
#[test]
fn rewrite_does_not_follow_an_existing_destination_symlink() {
    let directory = test_directory("symlink-destination");
    let input = directory.join("input.apk");
    let victim = directory.join("protected-data");
    let symlink = directory.join("alias.apk");
    write_stored_zip(
        &input,
        &[
            ("AndroidManifest.xml", b"<manifest/>"),
            ("classes.dex", b"original"),
        ],
    );
    fs::write(&victim, b"confidential").expect("victim data");
    std::os::unix::fs::symlink(&victim, &symlink).expect("symlink");
    let replacements = std::collections::BTreeMap::new();
    assert!(
        nexora_shield_package::rewrite_stored_entries(&input, &symlink, &replacements).is_err()
    );
    assert_eq!(fs::read(&victim).expect("read victim"), b"confidential");
    assert!(symlink.symlink_metadata().is_ok());
    cleanup(&directory);
}

fn test_directory(label: &str) -> PathBuf {
    let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "nexora-shield-phase-a-{}-{label}-{counter}",
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
        write_u32(
            &mut file,
            u32::try_from(data.len()).expect("fixture data length"),
        );
        write_u32(
            &mut file,
            u32::try_from(data.len()).expect("fixture data length"),
        );
        write_u16(
            &mut file,
            u16::try_from(name.len()).expect("fixture name length"),
        );
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
