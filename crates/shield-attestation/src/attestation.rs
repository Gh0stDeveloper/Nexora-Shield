use crate::error::{AttestationError, Result};
use crate::session::{AttestationChallenge, ChallengeNonce, SessionId};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAvailability {
    Available,
    TemporarilyUnavailable,
    Unsupported,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationEvidence {
    pub provider: String,
    pub application_id: String,
    pub build_id: String,
    pub purpose: String,
    pub session_id: SessionId,
    pub nonce: ChallengeNonce,
    pub token: Vec<u8>,
}

impl AttestationEvidence {
    pub fn validate_binding(&self, challenge: &AttestationChallenge) -> Result<()> {
        if self.provider.trim().is_empty()
            || self.provider.len() > 128
            || self.provider.chars().any(char::is_control)
        {
            return Err(AttestationError::InvalidProvider);
        }
        if self.token.is_empty() {
            return Err(AttestationError::EvidenceUnavailable);
        }

        if self.application_id != challenge.application_id
            || self.build_id != challenge.build_id
            || self.purpose != challenge.purpose
            || self.session_id != challenge.session_id
            || self.nonce != challenge.nonce
        {
            return Err(AttestationError::EvidenceBindingMismatch);
        }
        Ok(())
    }
}

impl Drop for AttestationEvidence {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl fmt::Debug for AttestationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttestationEvidence")
            .field("provider", &self.provider)
            .field("application_id", &self.application_id)
            .field("build_id", &self.build_id)
            .field("purpose", &self.purpose)
            .field("session_id", &self.session_id)
            .field("nonce", &self.nonce)
            .field("token", &"[REDACTED]")
            .field("token_bytes", &self.token.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Verified,
    Rejected,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationVerification {
    pub provider: String,
    pub verdict: AttestationVerdict,
    pub reason_code: String,
    pub verified_at_unix_ms: u64,
}

pub trait AttestationProvider {
    fn availability(&self) -> EvidenceAvailability;

    fn collect(&self, challenge: &AttestationChallenge) -> Result<AttestationEvidence>;
}

pub trait AttestationEvidenceVerifier {
    fn verify(
        &self,
        challenge: &AttestationChallenge,
        evidence: &AttestationEvidence,
        now_unix_ms: u64,
    ) -> Result<AttestationVerification>;
}
