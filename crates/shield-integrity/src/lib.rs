//! Nexora Shield Phase D integrity and anti-tamper engine.
//!
//! The engine binds protected builds to signing certificates and package
//! identity, fingerprints DEX regions/resources/native libraries, constructs a
//! certificate-rooted integrity graph, distributes checks redundantly and
//! produces non-destructive responses for detected tampering.

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

mod artifact;
mod distributed;
mod error;
mod graph;
mod hash;
mod identity;
mod manifest;
mod play_signing;
mod region;
mod response;
mod verify;

pub use artifact::{normalize_path, ArtifactCheck, ArtifactIntegrity, ArtifactKind};
pub use distributed::{CheckAssignment, DistributionPlan};
pub use error::{IntegrityError, Result};
pub use graph::{IntegrityEdge, IntegrityGraph, IntegrityNode, IntegrityNodeKind};
pub use hash::{hex_lower, Sha256Digest, SHA256_LEN};
pub use identity::{
    CertificateBinding, CertificateCheck, CertificateObservation, CertificatePolicy,
    PackageBinding, PackageCheck, PackageObservation,
};
pub use manifest::{
    DistributionConfig, IntegrityManifest, IntegrityManifestInput, INTEGRITY_MANIFEST_SCHEMA,
};
pub use play_signing::PlayAppSigningConfig;
pub use region::{DexIntegrity, IntegrityRegion, RegionCheck, DEFAULT_DEX_CHUNK_BYTES};
pub use response::{IntegrityResponse, IntegritySeverity, ResponsePolicy};
pub use verify::{
    IntegrityEvidence, IntegrityFailure, IntegrityFailureKind, IntegrityVerdict, IntegrityVerifier,
};
