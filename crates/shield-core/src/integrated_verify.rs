use super::native::{run, verify_library};
use crate::{runtime_smali::refuse, Result};
use nexora_shield_integrity::{CertificateObservation, PackageObservation, Sha256Digest};
use nexora_shield_native::{RuntimeApkGuard, RuntimeEntryKind, RuntimeImage};
use nexora_shield_package::{
    is_legacy_signature_entry, read_decoded_entry, read_zip_directory,
    verify_preserved_entry_payload, AndroidTools,
};
use nexora_shield_rasp::{
    DebugObservation, EmulatorObservation, HookInjectionObservation, PolicyMode, RaspResponse,
};
use std::{collections::BTreeSet, path::Path, process::Command, time::Duration};
pub(super) fn signer_digest(text: &str) -> Result<Sha256Digest> {
    let d = text
        .lines()
        .filter_map(|l| l.strip_prefix("Signer #1 certificate SHA-256 digest: "))
        .collect::<Vec<_>>();
    if d.len() != 1 || text.lines().any(|l| l.starts_with("Signer #2 ")) {
        return Err(refuse(
            "integrated APK requires exactly one observed signer",
        ));
    }
    d[0].parse()
        .map_err(|_| refuse("invalid signer SHA-256 returned by apksigner"))
}
pub(super) fn signing_payloads(before: &Path, after: &Path) -> Result<()> {
    let a = read_zip_directory(before)?;
    let b = read_zip_directory(after)?;
    let expected = a
        .entries
        .iter()
        .filter(|e| !is_legacy_signature_entry(&e.name))
        .map(|e| &e.name)
        .collect::<BTreeSet<_>>();
    let actual = b
        .entries
        .iter()
        .filter(|e| !is_legacy_signature_entry(&e.name))
        .map(|e| &e.name)
        .collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(refuse("signing changed final APK payload inventory"));
    }
    for e in &a.entries {
        if is_legacy_signature_entry(&e.name) {
            continue;
        }
        let out = b
            .entries
            .iter()
            .find(|v| v.name == e.name)
            .ok_or_else(|| refuse("signed APK lost a verified payload"))?;
        verify_preserved_entry_payload(before, e, after, out)?;
    }
    Ok(())
}
pub(super) fn final_guard(
    apk: &Path,
    image: &RuntimeImage,
    cert: Sha256Digest,
    version: u64,
    mode: PolicyMode,
) -> Result<usize> {
    let guard = RuntimeApkGuard::verify(
        apk,
        image,
        CertificateObservation::new([cert], [])
            .map_err(|_| refuse("invalid final signer observation"))?,
        PackageObservation::new(&image.application_id, version, None)
            .map_err(|_| refuse("invalid final package observation"))?,
    )
    .map_err(|_| refuse("signed final APK failed its actual integrity graph"))?;
    let normal = guard.evaluate(
        &DebugObservation::default(),
        &EmulatorObservation::default(),
        &HookInjectionObservation::default(),
    );
    if normal.effective_response != RaspResponse::Continue || normal.policy_mode != mode {
        return Err(refuse(
            "final RASP policy rejected normal host observations",
        ));
    }
    let traced = guard.evaluate(
        &DebugObservation {
            tracer_pid: Some(71),
            ..DebugObservation::default()
        },
        &EmulatorObservation::default(),
        &HookInjectionObservation::default(),
    );
    let expected = if mode == PolicyMode::ReportOnly {
        RaspResponse::Report
    } else {
        RaspResponse::DenySensitiveOperation
    };
    if traced.effective_response != expected {
        return Err(refuse("final RASP response differs from selected mode"));
    }
    verify_payloads(apk, image)?;
    Ok(guard.checks_verified)
}
fn verify_payloads(apk: &Path, image: &RuntimeImage) -> Result<()> {
    let directory = read_zip_directory(apk)?;
    let strings = image
        .entries
        .iter()
        .filter(|e| e.kind == RuntimeEntryKind::String)
        .map(|e| {
            image
                .decrypt_string(e.slot)
                .map_err(|_| refuse("final string authentication failed"))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut abis = BTreeSet::new();
    for e in &directory.entries {
        let bytes = read_decoded_entry(apk, e, 64 * 1024 * 1024)?;
        for value in &strings {
            for p in string_encodings(value) {
                if p.len() >= 8 && bytes.windows(p.len()).any(|v| v == p.as_slice()) {
                    return Err(refuse(
                        "selected plaintext string remains recoverable from final APK payloads",
                    ));
                }
            }
        }
        if let Some(abi) = e
            .name
            .strip_prefix("lib/")
            .and_then(|v| v.strip_suffix("/libnexora_shield_native.so"))
        {
            verify_library(&bytes, abi, image)?;
            abis.insert(abi.to_owned());
        }
    }
    if abis != BTreeSet::from(["arm64-v8a".to_owned(), "x86_64".to_owned()]) {
        return Err(refuse("final APK is missing a verified runtime ABI"));
    }
    image
        .authenticate()
        .map_err(|_| refuse("final runtime authentication failed"))?;
    Ok(())
}
fn string_encodings(value: &str) -> Vec<zeroize::Zeroizing<Vec<u8>>> {
    let units = zeroize::Zeroizing::new(value.encode_utf16().collect::<Vec<_>>());
    let mut m = zeroize::Zeroizing::new(Vec::new());
    for c in units.iter().copied() {
        let lo = c.to_le_bytes()[0];
        if (1..=0x7f).contains(&c) {
            m.push(lo);
        } else if c <= 0x7ff {
            m.extend_from_slice(&[0xc0 | (c >> 6).to_le_bytes()[0], 0x80 | (lo & 63)]);
        } else {
            m.extend_from_slice(&[
                0xe0 | (c >> 12).to_le_bytes()[0],
                0x80 | ((c >> 6).to_le_bytes()[0] & 63),
                0x80 | (lo & 63),
            ]);
        }
    }
    vec![
        zeroize::Zeroizing::new(value.as_bytes().to_vec()),
        zeroize::Zeroizing::new(units.iter().flat_map(|c| c.to_le_bytes()).collect()),
        m,
    ]
}
pub(super) fn final_alignment(tools: &AndroidTools, apk: &Path, work: &Path) -> Result<()> {
    let mut c = Command::new(&tools.zipalign);
    c.args(["-c", "-P", "16", "4"]).arg(apk);
    let _ = run(
        &mut c,
        work,
        Duration::from_secs(60),
        "final APK alignment verification",
    )?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signer_parser_requires_one_exact_certificate_digest() {
        let d = "a".repeat(64);
        assert!(signer_digest(&format!("Signer #1 certificate SHA-256 digest: {d}\n")).is_ok());
        for text in ["none".into(),format!("Signer #1 certificate SHA-256 digest: {d}\nSigner #2 certificate SHA-256 digest: {d}"),format!("Signer #1 certificate SHA-256 digest: {d}\nSigner #1 certificate SHA-256 digest: {d}"),"Signer #1 certificate SHA-256 digest: invalid".into()]{assert!(signer_digest(&text).is_err());}
    }
    #[test]
    fn exposure_probes_cover_dex_modified_utf8() {
        let p = string_encodings("a\0🔒");
        assert_eq!(
            p[2].as_slice(),
            &[97, 192, 128, 237, 160, 189, 237, 180, 146]
        );
        assert_ne!(p[0].as_slice(), p[2].as_slice());
    }
}
