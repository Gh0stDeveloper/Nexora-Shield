//! APK-byte evidence and real policy execution shared with the Android JNI adapter.
use crate::{RuntimeError, RuntimeImage};
use nexora_shield_integrity::{
    CertificateObservation, IntegrityEvidence, IntegrityVerifier, PackageObservation, Sha256Digest,
    SignedApkGuard, APK_GUARD_PATH, MAX_APK_GUARD_BYTES,
};
use nexora_shield_package::{is_legacy_signature_entry, read_decoded_entry, read_zip_directory};
use nexora_shield_rasp::{
    CompiledPolicy, DebugEvaluator, DebugObservation, EmulatorEvaluator, EmulatorObservation,
    HookInjectionEvaluator, HookInjectionObservation, PolicySpec, ResponseDecision, ResponseEngine,
    RiskEngine,
};
use std::{collections::BTreeMap, path::Path};

#[derive(Debug)]
pub struct RuntimeApkGuard {
    pub checks_verified: usize,
    policy: CompiledPolicy,
}

impl RuntimeApkGuard {
    pub fn verify(
        path: &Path,
        image: &RuntimeImage,
        certificate: CertificateObservation,
        package: PackageObservation,
    ) -> Result<Self, RuntimeError> {
        let public = image
            .guard_key
            .as_ref()
            .ok_or(RuntimeError("APK guard is not configured"))?;
        let directory = read_zip_directory(path).map_err(|_| failed())?;
        let entry = directory
            .entries
            .iter()
            .find(|e| e.name == APK_GUARD_PATH)
            .ok_or_else(failed)?;
        let bytes = read_decoded_entry(path, entry, MAX_APK_GUARD_BYTES).map_err(|_| failed())?;
        let payload = SignedApkGuard::verify(&bytes, public).map_err(|_| failed())?;
        let manifest = &payload.manifest;
        let cert = manifest
            .certificate
            .allowed_current
            .first()
            .ok_or_else(failed)?;
        let binding =
            serde_json::to_vec(&(cert, manifest.package.version_code, &payload.runtime_policy))
                .map_err(|_| failed())?;
        if image.guard_binding != Some(Sha256Digest::of(&binding).0) {
            return Err(failed());
        }
        if manifest.build_id != image.build_id
            || manifest.package.application_id != image.application_id
            || certificate.current != manifest.certificate.allowed_current
            || !certificate.lineage.is_empty()
        {
            return Err(failed());
        }
        let expected = payload.inventory();
        let mut observed = std::collections::BTreeSet::new();
        let mut total = 0usize;
        let mut evidence = IntegrityEvidence {
            certificate,
            package,
            dex_files: BTreeMap::new(),
            artifacts: BTreeMap::new(),
        };
        for entry in &directory.entries {
            if entry.name == APK_GUARD_PATH || is_legacy_signature_entry(&entry.name) {
                continue;
            }
            if !expected.contains(entry.name.as_str()) || !observed.insert(entry.name.as_str()) {
                return Err(failed());
            }
            let bytes = read_decoded_entry(path, entry, 64 * 1024 * 1024).map_err(|_| failed())?;
            total = total.checked_add(bytes.len()).ok_or_else(failed)?;
            if total > 256 * 1024 * 1024 {
                return Err(failed());
            }
            if manifest.dex_files.iter().any(|dex| dex.name == entry.name) {
                evidence.dex_files.insert(entry.name.clone(), bytes);
            } else {
                evidence.artifacts.insert(entry.name.clone(), bytes);
            }
        }
        if observed != expected {
            return Err(failed());
        }
        let verdict = IntegrityVerifier::verify_all(manifest, &evidence).map_err(|_| failed())?;
        if !verdict.clean || verdict.checks_passed != verdict.checks_total {
            return Err(failed());
        }
        let policy: PolicySpec =
            serde_json::from_slice(&payload.runtime_policy).map_err(|_| failed())?;
        let policy = CompiledPolicy::compile(policy).map_err(|_| failed())?;
        Ok(Self {
            checks_verified: verdict.checks_total,
            policy,
        })
    }

    pub fn evaluate(
        &self,
        debug: &DebugObservation,
        emulator: &EmulatorObservation,
        hooks: &HookInjectionObservation,
    ) -> ResponseDecision {
        let mut signals = DebugEvaluator::evaluate(debug);
        signals.extend(
            EmulatorEvaluator::evaluate(emulator)
                .signals()
                .iter()
                .cloned(),
        );
        signals.extend(
            HookInjectionEvaluator::evaluate(hooks)
                .signals()
                .iter()
                .cloned(),
        );
        ResponseEngine::decide(
            &self.policy,
            &RiskEngine::new(self.policy.thresholds()).evaluate(&signals),
        )
    }
}

fn failed() -> RuntimeError {
    RuntimeError("APK integrity verification failed")
}
