//! Internal APK guard verifier for host regressions; Android supplies its own observations.
use nexora_shield_integrity::{CertificateObservation, PackageObservation, Sha256Digest};
use nexora_shield_native::{RuntimeApkGuard, RuntimeImage};
use nexora_shield_rasp::{
    DebugObservation, EmulatorObservation, HookInjectionObservation, PolicyMode, RaspResponse,
};
use std::{fs, path::PathBuf};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 5 {
        return Err("usage: verify_runtime_guard <APK> <private-image> <signer-sha-file> <package> <version>".into());
    }
    let bytes = zeroize::Zeroizing::new(fs::read(&args[1])?);
    let image: RuntimeImage = serde_json::from_slice(&bytes)?;
    let signer = fs::read_to_string(&args[2])?.parse::<Sha256Digest>()?;
    let guard = RuntimeApkGuard::verify(
        &PathBuf::from(&args[0]),
        &image,
        CertificateObservation::new([signer], [])?,
        PackageObservation::new(&args[3], args[4].parse()?, None)?,
    )?;
    let normal = guard.evaluate(
        &DebugObservation::default(),
        &EmulatorObservation::default(),
        &HookInjectionObservation::default(),
    );
    if normal.effective_response != RaspResponse::Continue {
        return Err("Normal observation was denied".into());
    }
    let traced = guard.evaluate(
        &DebugObservation {
            tracer_pid: Some(71),
            ..DebugObservation::default()
        },
        &EmulatorObservation::default(),
        &HookInjectionObservation::default(),
    );
    let expected = if traced.policy_mode == PolicyMode::ReportOnly {
        RaspResponse::Report
    } else {
        RaspResponse::DenySensitiveOperation
    };
    if traced.effective_response != expected {
        return Err("RASP response contract failed".into());
    }
    println!(
        "APK_GRAPH_VERIFIED checks={} RASP_POLICY_VERIFIED",
        guard.checks_verified
    );
    Ok(())
}
