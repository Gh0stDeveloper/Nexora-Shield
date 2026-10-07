use std::fmt;

pub type Result<T> = std::result::Result<T, AttestationError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    InvalidApplicationId,
    InvalidBuildId,
    InvalidPurpose,
    InvalidProvider,
    InvalidFeature,
    InvalidPolicy(String),
    InvalidChallengeTtl,
    ChallengeExpired,
    ChallengeNotYetValid,
    UnknownSession,
    ReplayDetected,
    ChallengeMismatch,
    EvidenceBindingMismatch,
    EvidenceRejected(String),
    EvidenceUnavailable,
    SessionCapacityExceeded,
    SignatureKeyMismatch,
    SignatureAlgorithmMismatch,
    InvalidPolicySignature,
    PolicySequenceRollback { minimum: u64, observed: u64 },
    PolicyApplicationMismatch,
    PolicyNotYetValid,
    PolicySerialization(String),
    Authentication(String),
}

impl fmt::Display for AttestationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidApplicationId => formatter.write_str("application id is invalid"),
            Self::InvalidBuildId => formatter.write_str("build id is invalid"),
            Self::InvalidPurpose => formatter.write_str("attestation purpose is invalid"),
            Self::InvalidProvider => formatter.write_str("attestation provider is invalid"),
            Self::InvalidFeature => formatter.write_str("feature identifier is invalid"),
            Self::InvalidPolicy(message) => write!(formatter, "remote policy is invalid: {message}"),
            Self::InvalidChallengeTtl => formatter.write_str("challenge TTL is invalid"),
            Self::ChallengeExpired => formatter.write_str("attestation challenge has expired"),
            Self::ChallengeNotYetValid => {
                formatter.write_str("attestation challenge is not yet valid")
            }
            Self::UnknownSession => formatter.write_str("attestation session is unknown"),
            Self::ReplayDetected => formatter.write_str("attestation challenge was already consumed"),
            Self::ChallengeMismatch => {
                formatter.write_str("attestation challenge does not match registered session")
            }
            Self::EvidenceBindingMismatch => {
                formatter.write_str("attestation evidence is not bound to the challenge")
            }
            Self::EvidenceRejected(message) => {
                write!(formatter, "attestation evidence was rejected: {message}")
            }
            Self::EvidenceUnavailable => formatter.write_str("attestation evidence is unavailable"),
            Self::SessionCapacityExceeded => {
                formatter.write_str("attestation replay-guard capacity is exhausted")
            }
            Self::SignatureKeyMismatch => formatter.write_str("policy signature key is not trusted"),
            Self::SignatureAlgorithmMismatch => {
                formatter.write_str("policy signature algorithm is not supported")
            }
            Self::InvalidPolicySignature => formatter.write_str("remote policy signature is invalid"),
            Self::PolicySequenceRollback { minimum, observed } => write!(
                formatter,
                "remote policy sequence rollback: minimum {minimum}, observed {observed}"
            ),
            Self::PolicyApplicationMismatch => {
                formatter.write_str("remote policy targets a different application")
            }
            Self::PolicyNotYetValid => formatter.write_str("remote policy is not yet valid"),
            Self::PolicySerialization(message) => {
                write!(formatter, "remote policy serialization failed: {message}")
            }
            Self::Authentication(message) => write!(formatter, "authentication failed: {message}"),
        }
    }
}

impl std::error::Error for AttestationError {}
