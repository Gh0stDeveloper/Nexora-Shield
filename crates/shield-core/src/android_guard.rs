use super::{AndroidRuntimePlan, RuntimePayloads};
use crate::{runtime_smali::refuse, Result};
use ed25519_dalek::SigningKey;
use nexora_shield_dex::canonical_dex_index;
use nexora_shield_integrity::{
    ApkGuardPayload, ArtifactIntegrity, ArtifactKind, CertificateBinding, CertificatePolicy,
    DexIntegrity, DistributionConfig, IntegrityManifest, IntegrityManifestInput, PackageBinding,
    ResponsePolicy, Sha256Digest, SignedApkGuard, APK_GUARD_PATH, DEFAULT_DEX_CHUNK_BYTES,
};
use nexora_shield_package::{is_legacy_signature_entry, read_decoded_entry, read_zip_directory};
use nexora_shield_rasp::{CompiledPolicy, PolicyMode, PolicySpec};
use std::collections::BTreeSet;

pub(super) struct GuardBuild {
    key: SigningKey,
    certificate: [u8; 32],
    policy: PolicySpec,
}

impl AndroidRuntimePlan {
    /// Bind a signed startup graph to an independently provisioned build-private key.
    /// # Errors
    /// Rejects repeated binding, invalid policy or a weak signing key.
    pub fn bind_apk_guard(
        mut self,
        signing_key: &[u8; 32],
        certificate: [u8; 32],
        mode: PolicyMode,
    ) -> Result<Self> {
        if self.guard.is_some() {
            return Err(refuse("APK guard is already bound"));
        }
        let mut client_root = zeroize::Zeroizing::new([0u8; 32]);
        for (index, byte) in client_root.iter_mut().enumerate() {
            *byte = self.image.key_share_a[index] ^ self.image.key_share_b[index];
        }
        if signing_key == client_root.as_ref() {
            return Err(refuse(
                "APK graph signing key must be independent of client key material",
            ));
        }
        let key = SigningKey::from_bytes(signing_key);
        if key.verifying_key().is_weak() {
            return Err(refuse("weak APK guard key"));
        }
        let policy = PolicySpec {
            mode,
            ..PolicySpec::default()
        };
        CompiledPolicy::compile(policy.clone()).map_err(|_| refuse("invalid RASP policy"))?;
        let source = self.snapshot.path();
        let directory = read_zip_directory(&source)?;
        let entry = directory
            .entries
            .iter()
            .find(|entry| entry.name == "AndroidManifest.xml")
            .ok_or_else(|| refuse("missing manifest"))?;
        let bytes = read_decoded_entry(&source, entry, 16 * 1024 * 1024)?;
        let version = crate::android_binary_xml::runtime_manifest_version(&bytes)?;
        let policy_bytes =
            serde_json::to_vec(&policy).map_err(|_| refuse("invalid policy encoding"))?;
        let binding = serde_json::to_vec(&(Sha256Digest(certificate), version, &policy_bytes))
            .map_err(|_| refuse("invalid guard binding"))?;
        self.image.guard_key = Some(key.verifying_key().to_bytes());
        self.image.guard_binding = Some(Sha256Digest::of(&binding).0);
        self.guard = Some(GuardBuild {
            key,
            certificate,
            policy,
        });
        Ok(self)
    }

    pub(super) fn add_guard(
        &self,
        replacements: &mut RuntimePayloads,
        additions: &mut RuntimePayloads,
    ) -> Result<()> {
        let Some(guard) = &self.guard else {
            return Ok(());
        };
        let source = self.snapshot.path();
        let directory = read_zip_directory(&source)?;
        if directory.entries.iter().any(|e| e.name == APK_GUARD_PATH) {
            return Err(refuse("APK guard entry already exists"));
        }
        let entry = directory
            .entries
            .iter()
            .find(|e| e.name == "AndroidManifest.xml")
            .ok_or_else(|| refuse("missing manifest"))?;
        let original = read_decoded_entry(&source, entry, 16 * 1024 * 1024)?;
        let version = crate::android_binary_xml::runtime_manifest_version(&original)?;
        let authority = format!("{}.nexora.guard", self.image.application_id);
        let manifest = crate::android_binary_xml::inject_guard_provider(&original, &authority)?;
        replacements.insert("AndroidManifest.xml".into(), manifest);
        let original_names = directory
            .entries
            .iter()
            .map(|e| e.name.as_str())
            .collect::<BTreeSet<_>>();
        let mut payloads = Vec::new();
        for entry in &directory.entries {
            if is_legacy_signature_entry(&entry.name) {
                continue;
            }
            let bytes = if let Some(bytes) = replacements.get(&entry.name) {
                bytes.clone()
            } else {
                read_decoded_entry(&source, entry, 64 * 1024 * 1024)?
            };
            payloads.push((entry.name.clone(), bytes));
        }
        if additions
            .keys()
            .any(|name| original_names.contains(name.as_str()))
        {
            return Err(refuse("guard addition collision"));
        }
        payloads.extend(
            additions
                .iter()
                .map(|(name, bytes)| (name.clone(), bytes.clone())),
        );
        let (dex_files, artifacts) = guard_artifacts(payloads)?;
        let manifest = IntegrityManifest::build(IntegrityManifestInput {
            build_id: self.image.build_id.clone(),
            certificate: CertificateBinding::new(
                CertificatePolicy::ExactCurrent,
                [Sha256Digest(guard.certificate)],
                [],
            )
            .map_err(|_| refuse("invalid signer binding"))?,
            package: PackageBinding::new(&self.image.application_id, version, None)
                .map_err(|_| refuse("invalid package binding"))?,
            dex_files,
            artifacts,
            distribution: DistributionConfig::new(
                self.image
                    .fingerprint()
                    .map_err(|_| refuse("invalid guard seed"))?
                    .into_bytes(),
                5,
                2,
            ),
            response_policy: ResponsePolicy::default(),
        })
        .map_err(|_| refuse("APK graph generation failed"))?;
        let payload = ApkGuardPayload {
            schema: 1,
            manifest,
            runtime_policy: serde_json::to_vec(&guard.policy)
                .map_err(|_| refuse("RASP policy encoding failed"))?,
        };
        let signed = SignedApkGuard::sign(&payload, &guard.key)
            .map_err(|_| refuse("APK graph signing failed"))?;
        SignedApkGuard::verify(&signed, &guard.key.verifying_key().to_bytes())
            .map_err(|_| refuse("APK graph signature verification failed"))?;
        additions.insert(APK_GUARD_PATH.into(), signed);
        Ok(())
    }
}

fn guard_artifacts(
    payloads: Vec<(String, Vec<u8>)>,
) -> Result<(Vec<DexIntegrity>, Vec<ArtifactIntegrity>)> {
    let mut dex_files = Vec::new();
    let mut artifacts = Vec::new();
    let mut total = 0usize;
    for (name, bytes) in payloads {
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| refuse("guard budget overflow"))?;
        if total > 256 * 1024 * 1024 {
            return Err(refuse("guard decoded APK budget exceeded"));
        }
        if canonical_dex_index(&name).is_some() {
            dex_files.push(
                DexIntegrity::build(name, &bytes, DEFAULT_DEX_CHUNK_BYTES)
                    .map_err(|_| refuse("invalid guard DEX"))?,
            );
        } else {
            let kind = if name.starts_with("lib/") {
                ArtifactKind::Native
            } else {
                ArtifactKind::Resource
            };
            artifacts.push(
                ArtifactIntegrity::build(name, kind, &bytes)
                    .map_err(|_| refuse("unsupported guard artifact"))?,
            );
        }
    }
    Ok((dex_files, artifacts))
}
