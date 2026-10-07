//! Nexora Shield Phase I attestation and remote-policy engine.
//!
//! Phase I is optional for fully offline applications. When enabled, remote
//! evidence augments local RASP and integrity decisions; it never replaces
//! local controls or silently converts an offline-capable application into an
//! always-online one.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

mod attestation;
mod error;
mod policy;
mod privacy;
mod server;
mod session;

pub use attestation::{
    AttestationEvidence, AttestationEvidenceVerifier, AttestationProvider, AttestationVerdict,
    AttestationVerification, EvidenceAvailability,
};
pub use error::{AttestationError, Result};
pub use policy::{
    BuildRevocation, FeatureAccessDecision, FeatureDecisionReason, FeatureEvaluation,
    FeatureEvaluationContext, FeaturePolicy, OfflineAction, OfflinePolicy, PolicyAuthenticator,
    PolicySignatureAlgorithm, PolicySignatureVerifier, PolicySigner, RemotePolicyPayload,
    SampleHmacPolicyAuthenticator, SignedPolicyEnvelope, VerifiedRemotePolicy,
    MAX_OFFLINE_STALENESS_MS, REMOTE_POLICY_SCHEMA,
};
pub use privacy::{PrivacyAudit, PrivacyAuditReport, PrivacyDataCategory};
pub use server::{
    AttestationRequest, SampleHmacEvidenceAuthenticator, SampleRemotePolicyServer,
    ServerAttestationResponse,
};
pub use session::{
    AttestationChallenge, ChallengeDeriver, ChallengeNonce, ReplayGuard, SessionId,
    DEFAULT_CHALLENGE_TTL_MS, MAX_CHALLENGE_TTL_MS,
};
