//! Nexora Shield Phase N production release contracts.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

mod api;
mod compatibility;
mod error;
mod migration;
mod provenance;
mod qualification;
mod version;

pub use api::{ApiSurface, MINIMUM_ANDROID_SDK, PUBLIC_API_CONTRACT_VERSION, STABLE_CONFIG_SCHEMA};
pub use compatibility::CompatibilityMatrix;
pub use error::{ReleaseError, Result};
pub use migration::{migrate_to_current, MigrationOutcome};
pub use provenance::ArtifactDigest;
pub use qualification::{FeedbackStatus, QualificationPolicy};
pub use version::{ReleaseChannel, ReleaseVersion};
