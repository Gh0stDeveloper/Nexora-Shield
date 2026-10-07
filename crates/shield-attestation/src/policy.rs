use crate::attestation::AttestationVerdict;
use crate::error::{AttestationError, Result};
use hmac::{Hmac, Mac};
use nexora_shield_rasp::RiskLevel;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

pub const REMOTE_POLICY_SCHEMA: u32 = 1;
pub const MAX_OFFLINE_STALENESS_MS: u64 = 30 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySignatureAlgorithm {
    Ed25519,
    Es256,
    HmacSha256Sample,
}

impl PolicySignatureAlgorithm {
    const fn code(self) -> u8 {
        match self {
            Self::Ed25519 => 1,
            Self::Es256 => 2,
            Self::HmacSha256Sample => 250,
        }
    }
}

pub trait PolicySigner {
    fn key_id(&self) -> &str;

    fn algorithm(&self) -> PolicySignatureAlgorithm;

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
}

pub trait PolicySignatureVerifier {
    fn verify(
        &self,
        key_id: &str,
        algorithm: PolicySignatureAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()>;
}

pub trait PolicyAuthenticator: PolicySigner + PolicySignatureVerifier {}

impl<T> PolicyAuthenticator for T where T: PolicySigner + PolicySignatureVerifier {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineAction {
    Allow,
    Degrade,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflinePolicy {
    pub max_staleness_ms: u64,
    pub default_action: OfflineAction,
}

impl Default for OfflinePolicy {
    fn default() -> Self {
        Self {
            max_staleness_ms: 24 * 60 * 60 * 1000,
            default_action: OfflineAction::Degrade,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildRevocation {
    pub reason_code: String,
    pub revoked_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeaturePolicy {
    pub max_local_risk: RiskLevel,
    pub require_verified_attestation: bool,
    pub offline_action: Option<OfflineAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemotePolicyPayload {
    pub schema_version: u32,
    pub policy_id: String,
    pub sequence: u64,
    pub application_id: String,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub offline: OfflinePolicy,
    pub revoked_builds: BTreeMap<String, BuildRevocation>,
    pub features: BTreeMap<String, FeaturePolicy>,
}

impl RemotePolicyPayload {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != REMOTE_POLICY_SCHEMA {
            return Err(AttestationError::InvalidPolicy(format!(
                "unsupported schema {}",
                self.schema_version
            )));
        }
        validate_identifier(&self.policy_id, "policy_id")?;
        validate_identifier(&self.application_id, "application_id")?;
        if self.sequence == 0 {
            return Err(AttestationError::InvalidPolicy(
                "sequence must be non-zero".into(),
            ));
        }
        if self.expires_unix_ms <= self.issued_unix_ms {
            return Err(AttestationError::InvalidPolicy(
                "expires_unix_ms must be greater than issued_unix_ms".into(),
            ));
        }
        if self.offline.max_staleness_ms > MAX_OFFLINE_STALENESS_MS {
            return Err(AttestationError::InvalidPolicy(format!(
                "offline staleness exceeds {MAX_OFFLINE_STALENESS_MS} ms"
            )));
        }

        for (build_id, revocation) in &self.revoked_builds {
            validate_identifier(build_id, "revoked build id")?;
            validate_identifier(&revocation.reason_code, "revocation reason")?;
        }
        for feature in self.features.keys() {
            validate_identifier(feature, "feature")?;
        }
        Ok(())
    }

    #[must_use]
    pub fn is_build_revoked(&self, build_id: &str) -> bool {
        self.revoked_builds.contains_key(build_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPolicyEnvelope {
    pub payload: RemotePolicyPayload,
    pub key_id: String,
    pub algorithm: PolicySignatureAlgorithm,
    pub signature: Vec<u8>,
}

impl SignedPolicyEnvelope {
    pub fn sign(payload: RemotePolicyPayload, signer: &impl PolicySigner) -> Result<Self> {
        payload.validate()?;
        validate_identifier(signer.key_id(), "policy key id")?;

        let key_id = signer.key_id().to_owned();
        let algorithm = signer.algorithm();
        let message = signing_bytes(&payload, &key_id, algorithm)?;
        let signature = signer.sign(&message)?;
        if signature.is_empty() {
            return Err(AttestationError::InvalidPolicySignature);
        }

        Ok(Self {
            payload,
            key_id,
            algorithm,
            signature,
        })
    }

    pub fn verify(
        &self,
        verifier: &impl PolicySignatureVerifier,
        expected_application_id: &str,
        minimum_sequence: u64,
        now_unix_ms: u64,
    ) -> Result<VerifiedRemotePolicy> {
        let message = signing_bytes(&self.payload, &self.key_id, self.algorithm)?;
        verifier.verify(&self.key_id, self.algorithm, &message, &self.signature)?;

        self.payload.validate()?;
        if self.payload.application_id != expected_application_id {
            return Err(AttestationError::PolicyApplicationMismatch);
        }
        if self.payload.sequence < minimum_sequence {
            return Err(AttestationError::PolicySequenceRollback {
                minimum: minimum_sequence,
                observed: self.payload.sequence,
            });
        }
        if now_unix_ms < self.payload.issued_unix_ms {
            return Err(AttestationError::PolicyNotYetValid);
        }

        Ok(VerifiedRemotePolicy {
            payload: self.payload.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRemotePolicy {
    payload: RemotePolicyPayload,
}

impl VerifiedRemotePolicy {
    #[must_use]
    pub const fn payload(&self) -> &RemotePolicyPayload {
        &self.payload
    }

    pub fn evaluate(&self, context: &FeatureEvaluationContext) -> Result<FeatureEvaluation> {
        validate_identifier(&context.build_id, "build_id")?;
        validate_identifier(&context.feature, "feature")?;

        if self.payload.is_build_revoked(&context.build_id) {
            return Ok(FeatureEvaluation::deny(
                FeatureDecisionReason::BuildRevoked,
                self.payload.sequence,
            ));
        }

        let Some(feature_policy) = self.payload.features.get(&context.feature) else {
            return Ok(FeatureEvaluation::deny(
                FeatureDecisionReason::UnknownFeature,
                self.payload.sequence,
            ));
        };

        if context.now_unix_ms > self.payload.expires_unix_ms {
            return Ok(self.expired_policy_decision(feature_policy, context));
        }

        if context.local_risk > feature_policy.max_local_risk {
            return Ok(FeatureEvaluation::deny(
                FeatureDecisionReason::LocalRiskAboveThreshold,
                self.payload.sequence,
            ));
        }

        match context.attestation {
            AttestationVerdict::Rejected => Ok(FeatureEvaluation::deny(
                FeatureDecisionReason::AttestationRejected,
                self.payload.sequence,
            )),
            AttestationVerdict::Verified => Ok(FeatureEvaluation::allow(
                FeatureDecisionReason::PolicySatisfied,
                self.payload.sequence,
            )),
            AttestationVerdict::Unavailable if feature_policy.require_verified_attestation => {
                if context.online {
                    Ok(FeatureEvaluation {
                        decision: FeatureAccessDecision::RequireOnlineVerification,
                        reason: FeatureDecisionReason::AttestationRequired,
                        policy_sequence: self.payload.sequence,
                    })
                } else {
                    Ok(self
                        .offline_decision(feature_policy, FeatureDecisionReason::OfflineFallback))
                }
            }
            AttestationVerdict::Unavailable => Ok(FeatureEvaluation::allow(
                FeatureDecisionReason::PolicySatisfied,
                self.payload.sequence,
            )),
        }
    }

    fn expired_policy_decision(
        &self,
        feature_policy: &FeaturePolicy,
        context: &FeatureEvaluationContext,
    ) -> FeatureEvaluation {
        if context.online {
            return FeatureEvaluation {
                decision: FeatureAccessDecision::RequireOnlineVerification,
                reason: FeatureDecisionReason::PolicyExpired,
                policy_sequence: self.payload.sequence,
            };
        }

        let stale_by = context
            .now_unix_ms
            .saturating_sub(self.payload.expires_unix_ms);
        if stale_by > self.payload.offline.max_staleness_ms {
            return FeatureEvaluation::deny(
                FeatureDecisionReason::PolicyTooStale,
                self.payload.sequence,
            );
        }

        self.offline_decision(feature_policy, FeatureDecisionReason::OfflineCachedPolicy)
    }

    fn offline_decision(
        &self,
        feature_policy: &FeaturePolicy,
        reason: FeatureDecisionReason,
    ) -> FeatureEvaluation {
        let action = feature_policy
            .offline_action
            .unwrap_or(self.payload.offline.default_action);
        let decision = match action {
            OfflineAction::Allow => FeatureAccessDecision::Allow,
            OfflineAction::Degrade => FeatureAccessDecision::Degraded,
            OfflineAction::Deny => FeatureAccessDecision::Deny,
        };
        FeatureEvaluation {
            decision,
            reason,
            policy_sequence: self.payload.sequence,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureEvaluationContext {
    pub build_id: String,
    pub feature: String,
    pub local_risk: RiskLevel,
    pub attestation: AttestationVerdict,
    pub online: bool,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureAccessDecision {
    Allow,
    Degraded,
    RequireOnlineVerification,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureDecisionReason {
    PolicySatisfied,
    BuildRevoked,
    UnknownFeature,
    LocalRiskAboveThreshold,
    AttestationRejected,
    AttestationRequired,
    PolicyExpired,
    PolicyTooStale,
    OfflineFallback,
    OfflineCachedPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureEvaluation {
    pub decision: FeatureAccessDecision,
    pub reason: FeatureDecisionReason,
    pub policy_sequence: u64,
}

impl FeatureEvaluation {
    const fn allow(reason: FeatureDecisionReason, policy_sequence: u64) -> Self {
        Self {
            decision: FeatureAccessDecision::Allow,
            reason,
            policy_sequence,
        }
    }

    const fn deny(reason: FeatureDecisionReason, policy_sequence: u64) -> Self {
        Self {
            decision: FeatureAccessDecision::Deny,
            reason,
            policy_sequence,
        }
    }
}

pub struct SampleHmacPolicyAuthenticator {
    key_id: String,
    key: [u8; 32],
}

impl SampleHmacPolicyAuthenticator {
    pub fn new(key_id: impl Into<String>, key: [u8; 32]) -> Result<Self> {
        let key_id = key_id.into();
        validate_identifier(&key_id, "policy key id")?;
        Ok(Self { key_id, key })
    }
}

impl PolicySigner for SampleHmacPolicyAuthenticator {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn algorithm(&self) -> PolicySignatureAlgorithm {
        PolicySignatureAlgorithm::HmacSha256Sample
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|error| AttestationError::Authentication(error.to_string()))?;
        mac.update(message);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

impl PolicySignatureVerifier for SampleHmacPolicyAuthenticator {
    fn verify(
        &self,
        key_id: &str,
        algorithm: PolicySignatureAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        if key_id != self.key_id {
            return Err(AttestationError::SignatureKeyMismatch);
        }
        if algorithm != PolicySignatureAlgorithm::HmacSha256Sample {
            return Err(AttestationError::SignatureAlgorithmMismatch);
        }

        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|error| AttestationError::Authentication(error.to_string()))?;
        mac.update(message);
        mac.verify_slice(signature)
            .map_err(|_| AttestationError::InvalidPolicySignature)
    }
}

impl Drop for SampleHmacPolicyAuthenticator {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl fmt::Debug for SampleHmacPolicyAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleHmacPolicyAuthenticator")
            .field("key_id", &self.key_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

fn signing_bytes(
    payload: &RemotePolicyPayload,
    key_id: &str,
    algorithm: PolicySignatureAlgorithm,
) -> Result<Vec<u8>> {
    validate_identifier(key_id, "policy key id")?;
    let encoded = serde_json::to_vec(payload)
        .map_err(|error| AttestationError::PolicySerialization(error.to_string()))?;

    let mut message = Vec::with_capacity(64 + key_id.len() + encoded.len());
    append_component(&mut message, b"nexora-shield/remote-policy/v1");
    append_component(&mut message, key_id.as_bytes());
    append_component(&mut message, &[algorithm.code()]);
    append_component(&mut message, &encoded);
    Ok(message)
}

fn append_component(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    output.extend_from_slice(value);
}

fn validate_identifier(value: &str, name: &str) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > 256
        || value.as_bytes().contains(&0)
        || value.chars().any(char::is_control)
    {
        return Err(AttestationError::InvalidPolicy(format!(
            "{name} is empty or malformed"
        )));
    }
    Ok(())
}
