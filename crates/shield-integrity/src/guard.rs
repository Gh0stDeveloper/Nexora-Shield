//! Detached, signed APK graph: never hash the envelope into itself.
use crate::{IntegrityError, IntegrityManifest, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const APK_GUARD_PATH: &str = "assets/nexora-shield/guard.v1";
pub const MAX_APK_GUARD_BYTES: usize = 4 * 1024 * 1024;
const DOMAIN: &[u8] = b"NexoraShield:O1:APK-guard:v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApkGuardPayload {
    pub schema: u32,
    pub manifest: IntegrityManifest,
    /// Opaque signed runtime policy, validated by the consuming policy engine.
    pub runtime_policy: Vec<u8>,
}

impl ApkGuardPayload {
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1
            || self.runtime_policy.is_empty()
            || self.runtime_policy.len() > 16 * 1024
        {
            return Err(invalid());
        }
        if self.manifest.graph.nodes.len() > 8192
            || self.manifest.artifacts.len() > 4096
            || self.manifest.dex_files.len() > 64
        {
            return Err(invalid());
        }
        self.manifest.validate()?;
        let names = self.inventory();
        if names.len() != self.manifest.dex_files.len() + self.manifest.artifacts.len()
            || names.contains(APK_GUARD_PATH)
            || self.manifest.dex_files.is_empty()
            || self.manifest.certificate.allowed_current.len() != 1
            || !self.manifest.certificate.allowed_lineage.is_empty()
            || self.manifest.certificate.policy != crate::CertificatePolicy::ExactCurrent
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn inventory(&self) -> BTreeSet<&str> {
        self.manifest
            .dex_files
            .iter()
            .map(|dex| dex.name.as_str())
            .chain(
                self.manifest
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.path.as_str()),
            )
            .collect()
    }
}

/// The key is provisioned independently; it must never be derived from client key shares.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApkGuard {
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl std::fmt::Debug for SignedApkGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedApkGuard")
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl SignedApkGuard {
    pub fn sign(payload: &ApkGuardPayload, key: &SigningKey) -> Result<Vec<u8>> {
        payload.validate()?;
        let payload = serde_json::to_vec(payload)?;
        let envelope = Self {
            signature: key.sign(&message(&payload)?).to_bytes().to_vec(),
            payload,
        };
        let encoded = serde_json::to_vec(&envelope)?;
        if encoded.len() > MAX_APK_GUARD_BYTES {
            return Err(invalid());
        }
        Ok(encoded)
    }

    pub fn verify(bytes: &[u8], pinned_key: &[u8; 32]) -> Result<ApkGuardPayload> {
        if bytes.len() > MAX_APK_GUARD_BYTES {
            return Err(invalid());
        }
        let envelope: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        let public = VerifyingKey::from_bytes(pinned_key).map_err(|_| invalid())?;
        let signature = Signature::from_slice(&envelope.signature).map_err(|_| invalid())?;
        public
            .verify_strict(&message(&envelope.payload)?, &signature)
            .map_err(|_| invalid())?;
        let payload: ApkGuardPayload =
            serde_json::from_slice(&envelope.payload).map_err(|_| invalid())?;
        payload.validate()?;
        Ok(payload)
    }
}

fn message(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_APK_GUARD_BYTES {
        return Err(invalid());
    }
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(payload);
    Ok(message)
}

fn invalid() -> IntegrityError {
    IntegrityError::InvalidManifest("APK guard authentication or contract failed".into())
}
