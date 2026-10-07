use crate::attestation::{
    AttestationEvidence, AttestationEvidenceVerifier, AttestationProvider, AttestationVerdict,
    AttestationVerification, EvidenceAvailability,
};
use crate::error::{AttestationError, Result};
use crate::session::{AttestationChallenge, ReplayGuard, SessionId};
use hmac::{Hmac, Mac};
use nexora_shield_rasp::RiskLevel;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationRequest {
    pub challenge: AttestationChallenge,
    pub evidence: AttestationEvidence,
    pub feature: String,
    pub local_risk: RiskLevel,
}

impl fmt::Debug for AttestationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttestationRequest")
            .field("challenge", &self.challenge)
            .field("evidence", &self.evidence)
            .field("feature", &self.feature)
            .field("local_risk", &self.local_risk)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerAttestationResponse {
    pub session_id: SessionId,
    pub application_id: String,
    pub build_id: String,
    pub feature: String,
    pub local_risk: RiskLevel,
    pub verification: AttestationVerification,
}

#[derive(Debug)]
pub struct SampleRemotePolicyServer<V> {
    replay_guard: ReplayGuard,
    verifier: V,
}

impl<V> SampleRemotePolicyServer<V>
where
    V: AttestationEvidenceVerifier,
{
    #[must_use]
    pub fn new(verifier: V, max_sessions: usize) -> Self {
        Self {
            replay_guard: ReplayGuard::new(max_sessions),
            verifier,
        }
    }

    pub fn register_challenge(
        &mut self,
        challenge: AttestationChallenge,
        now_unix_ms: u64,
    ) -> Result<()> {
        self.replay_guard.register(challenge, now_unix_ms)
    }

    pub fn verify_request(
        &mut self,
        request: &AttestationRequest,
        now_unix_ms: u64,
    ) -> Result<ServerAttestationResponse> {
        validate_feature(&request.feature)?;
        request.evidence.validate_binding(&request.challenge)?;

        // Consume before calling the provider verifier. A rejected or malformed
        // evidence token must not leave a reusable server challenge.
        self.replay_guard.consume(&request.challenge, now_unix_ms)?;

        let verification =
            self.verifier
                .verify(&request.challenge, &request.evidence, now_unix_ms)?;
        if verification.provider != request.evidence.provider {
            return Err(AttestationError::EvidenceBindingMismatch);
        }

        Ok(ServerAttestationResponse {
            session_id: request.challenge.session_id,
            application_id: request.challenge.application_id.clone(),
            build_id: request.challenge.build_id.clone(),
            feature: request.feature.clone(),
            local_risk: request.local_risk,
            verification,
        })
    }

    #[must_use]
    pub fn active_sessions(&self) -> usize {
        self.replay_guard.len()
    }
}

pub struct SampleHmacEvidenceAuthenticator {
    provider: String,
    key: [u8; 32],
}

impl SampleHmacEvidenceAuthenticator {
    pub fn new(provider: impl Into<String>, key: [u8; 32]) -> Result<Self> {
        let provider = provider.into();
        if provider.trim().is_empty()
            || provider.len() > 128
            || provider.chars().any(char::is_control)
        {
            return Err(AttestationError::InvalidProvider);
        }
        Ok(Self { provider, key })
    }

    fn token_for(&self, challenge: &AttestationChallenge) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|error| AttestationError::Authentication(error.to_string()))?;
        append_component(&mut mac, b"nexora-shield/sample-attestation-token/v1");
        append_component(&mut mac, challenge.application_id.as_bytes());
        append_component(&mut mac, challenge.build_id.as_bytes());
        append_component(&mut mac, challenge.purpose.as_bytes());
        append_component(&mut mac, challenge.session_id.as_bytes());
        append_component(&mut mac, challenge.nonce.as_bytes());
        append_component(&mut mac, &challenge.issued_unix_ms.to_le_bytes());
        append_component(&mut mac, &challenge.expires_unix_ms.to_le_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

impl AttestationProvider for SampleHmacEvidenceAuthenticator {
    fn availability(&self) -> EvidenceAvailability {
        EvidenceAvailability::Available
    }

    fn collect(&self, challenge: &AttestationChallenge) -> Result<AttestationEvidence> {
        Ok(AttestationEvidence {
            provider: self.provider.clone(),
            application_id: challenge.application_id.clone(),
            build_id: challenge.build_id.clone(),
            purpose: challenge.purpose.clone(),
            session_id: challenge.session_id,
            nonce: challenge.nonce,
            token: self.token_for(challenge)?,
        })
    }
}

impl AttestationEvidenceVerifier for SampleHmacEvidenceAuthenticator {
    fn verify(
        &self,
        challenge: &AttestationChallenge,
        evidence: &AttestationEvidence,
        now_unix_ms: u64,
    ) -> Result<AttestationVerification> {
        challenge.validate_at(now_unix_ms)?;
        evidence.validate_binding(challenge)?;

        if evidence.provider != self.provider {
            return Err(AttestationError::InvalidProvider);
        }

        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|error| AttestationError::Authentication(error.to_string()))?;
        append_component(&mut mac, b"nexora-shield/sample-attestation-token/v1");
        append_component(&mut mac, challenge.application_id.as_bytes());
        append_component(&mut mac, challenge.build_id.as_bytes());
        append_component(&mut mac, challenge.purpose.as_bytes());
        append_component(&mut mac, challenge.session_id.as_bytes());
        append_component(&mut mac, challenge.nonce.as_bytes());
        append_component(&mut mac, &challenge.issued_unix_ms.to_le_bytes());
        append_component(&mut mac, &challenge.expires_unix_ms.to_le_bytes());
        mac.verify_slice(&evidence.token)
            .map_err(|_| AttestationError::EvidenceRejected("sample token MAC mismatch".into()))?;


        Ok(AttestationVerification {
            provider: self.provider.clone(),
            verdict: AttestationVerdict::Verified,
            reason_code: "sample_token_verified".into(),
            verified_at_unix_ms: now_unix_ms,
        })
    }
}

impl Drop for SampleHmacEvidenceAuthenticator {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl fmt::Debug for SampleHmacEvidenceAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleHmacEvidenceAuthenticator")
            .field("provider", &self.provider)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

fn validate_feature(feature: &str) -> Result<()> {
    if feature.trim().is_empty()
        || feature.len() > 256
        || feature.as_bytes().contains(&0)
        || feature.chars().any(char::is_control)
    {
        return Err(AttestationError::InvalidFeature);
    }
    Ok(())
}

fn append_component(mac: &mut HmacSha256, value: &[u8]) {
    mac.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    mac.update(value);
}
