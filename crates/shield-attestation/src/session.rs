use crate::error::{AttestationError, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

pub const DEFAULT_CHALLENGE_TTL_MS: u64 = 120_000;
pub const MAX_CHALLENGE_TTL_MS: u64 = 10 * 60_000;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct SessionId(pub [u8; 16]);

impl SessionId {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChallengeNonce(pub [u8; 32]);

impl ChallengeNonce {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationChallenge {
    pub application_id: String,
    pub build_id: String,
    pub purpose: String,
    pub session_id: SessionId,
    pub nonce: ChallengeNonce,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
}

impl AttestationChallenge {
    pub fn validate_at(&self, now_unix_ms: u64) -> Result<()> {
        validate_identifier(&self.application_id, AttestationError::InvalidApplicationId)?;
        validate_identifier(&self.build_id, AttestationError::InvalidBuildId)?;
        validate_identifier(&self.purpose, AttestationError::InvalidPurpose)?;

        if self.expires_unix_ms <= self.issued_unix_ms {
            return Err(AttestationError::InvalidChallengeTtl);
        }
        if now_unix_ms < self.issued_unix_ms {
            return Err(AttestationError::ChallengeNotYetValid);
        }
        if now_unix_ms > self.expires_unix_ms {
            return Err(AttestationError::ChallengeExpired);
        }
        Ok(())
    }
}

pub struct ChallengeDeriver {
    key: [u8; 32],
    server_instance_id: [u8; 16],
    counter: u64,
}

impl ChallengeDeriver {
    #[must_use]
    pub const fn new(key: [u8; 32], server_instance_id: [u8; 16]) -> Self {
        Self {
            key,
            server_instance_id,
            counter: 0,
        }
    }

    pub fn issue(
        &mut self,
        application_id: &str,
        build_id: &str,
        purpose: &str,
        now_unix_ms: u64,
        ttl_ms: u64,
    ) -> Result<AttestationChallenge> {
        validate_identifier(application_id, AttestationError::InvalidApplicationId)?;
        validate_identifier(build_id, AttestationError::InvalidBuildId)?;
        validate_identifier(purpose, AttestationError::InvalidPurpose)?;

        if ttl_ms == 0 || ttl_ms > MAX_CHALLENGE_TTL_MS {
            return Err(AttestationError::InvalidChallengeTtl);
        }
        let expires_unix_ms = now_unix_ms
            .checked_add(ttl_ms)
            .ok_or(AttestationError::InvalidChallengeTtl)?;

        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| AttestationError::Authentication("challenge counter overflow".into()))?;

        let session_digest = self.derive_digest(
            b"nexora-shield/attestation-session/v1",
            application_id,
            build_id,
            purpose,
            now_unix_ms,
            self.counter,
            &[],
        )?;
        let mut session_bytes = [0_u8; 16];
        session_bytes.copy_from_slice(&session_digest[..16]);
        let session_id = SessionId(session_bytes);

        let nonce_digest = self.derive_digest(
            b"nexora-shield/attestation-nonce/v1",
            application_id,
            build_id,
            purpose,
            now_unix_ms,
            self.counter,
            session_id.as_bytes(),
        )?;

        Ok(AttestationChallenge {
            application_id: application_id.to_owned(),
            build_id: build_id.to_owned(),
            purpose: purpose.to_owned(),
            session_id,
            nonce: ChallengeNonce(nonce_digest),
            issued_unix_ms: now_unix_ms,
            expires_unix_ms,
        })
    }

    fn derive_digest(
        &self,
        domain: &[u8],
        application_id: &str,
        build_id: &str,
        purpose: &str,
        now_unix_ms: u64,
        counter: u64,
        extra: &[u8],
    ) -> Result<[u8; 32]> {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|error| AttestationError::Authentication(error.to_string()))?;
        update_component(&mut mac, domain);
        update_component(&mut mac, &self.server_instance_id);
        update_component(&mut mac, application_id.as_bytes());
        update_component(&mut mac, build_id.as_bytes());
        update_component(&mut mac, purpose.as_bytes());
        update_component(&mut mac, &now_unix_ms.to_le_bytes());
        update_component(&mut mac, &counter.to_le_bytes());
        update_component(&mut mac, extra);
        Ok(mac.finalize().into_bytes().into())
    }
}

impl Drop for ChallengeDeriver {
    fn drop(&mut self) {
        self.key.zeroize();
        self.server_instance_id.zeroize();
        self.counter.zeroize();
    }
}

impl fmt::Debug for ChallengeDeriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChallengeDeriver")
            .field("key", &"[REDACTED]")
            .field("server_instance_id", &"[REDACTED]")
            .field("counter", &self.counter)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionRecord {
    challenge: AttestationChallenge,
    consumed: bool,
}

#[derive(Debug, Clone)]
pub struct ReplayGuard {
    sessions: BTreeMap<SessionId, SessionRecord>,
    max_sessions: usize,
}

impl ReplayGuard {
    #[must_use]
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: BTreeMap::new(),
            max_sessions,
        }
    }

    pub fn register(
        &mut self,
        challenge: AttestationChallenge,
        now_unix_ms: u64,
    ) -> Result<()> {
        challenge.validate_at(now_unix_ms)?;
        self.prune_expired(now_unix_ms);

        if self.sessions.contains_key(&challenge.session_id) {
            return Err(AttestationError::ReplayDetected);
        }
        if self.max_sessions == 0 || self.sessions.len() >= self.max_sessions {
            return Err(AttestationError::SessionCapacityExceeded);
        }

        self.sessions.insert(
            challenge.session_id,
            SessionRecord {
                challenge,
                consumed: false,
            },
        );
        Ok(())
    }

    pub fn consume(
        &mut self,
        challenge: &AttestationChallenge,
        now_unix_ms: u64,
    ) -> Result<()> {
        challenge.validate_at(now_unix_ms)?;
        self.prune_expired(now_unix_ms);

        let record = self
            .sessions
            .get_mut(&challenge.session_id)
            .ok_or(AttestationError::UnknownSession)?;

        if record.consumed {
            return Err(AttestationError::ReplayDetected);
        }
        if !challenge_matches(&record.challenge, challenge) {
            return Err(AttestationError::ChallengeMismatch);
        }

        record.consumed = true;
        Ok(())
    }

    pub fn prune_expired(&mut self, now_unix_ms: u64) {
        self.sessions
            .retain(|_, record| record.challenge.expires_unix_ms >= now_unix_ms);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new(4096)
    }
}

fn challenge_matches(expected: &AttestationChallenge, observed: &AttestationChallenge) -> bool {
    expected.application_id == observed.application_id
        && expected.build_id == observed.build_id
        && expected.purpose == observed.purpose
        && expected.session_id == observed.session_id
        && expected.issued_unix_ms == observed.issued_unix_ms
        && expected.expires_unix_ms == observed.expires_unix_ms
        && expected
            .nonce
            .as_bytes()
            .ct_eq(observed.nonce.as_bytes())
            .unwrap_u8()
            == 1
}

fn validate_identifier(value: &str, error: AttestationError) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > 256
        || value.as_bytes().contains(&0)
        || value.chars().any(char::is_control)
    {
        return Err(error);
    }
    Ok(())
}

fn update_component(mac: &mut HmacSha256, value: &[u8]) {
    mac.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    mac.update(value);
}
