//! Nexora Shield Phase C data-protection engine.
//!
//! This crate provides sensitivity classification, authenticated encrypted
//! containers, per-build/per-item key derivation, decrypt-on-use lifetime
//! controls, typed constant protection, safe resource bundles, private
//! metadata and plaintext-exposure measurement.

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

mod benchmark;
mod constant;
mod container;
mod error;
mod key;
mod metadata;
mod resource;
mod runtime;
mod sensitivity;

pub use benchmark::{ExposureBenchmark, ExposureFinding, ExposureProbe, ExposureReport};
pub use constant::{
    decode as decode_constant, encode as encode_constant, protect_constant, unprotect_constant,
    ConstantValue,
};
pub use container::{
    inspect as inspect_container, open, seal, ContainerInfo, ContainerKind, CONTAINER_HEADER_LEN,
    CONTAINER_MAGIC, CONTAINER_VERSION, DEFAULT_MAX_PLAINTEXT_BYTES,
};
pub use error::{DataProtectionError, Result};
pub use key::{
    hex_lower, sha256, BuildIdentity, KeyDomain, KeySchedule, CONTENT_KEY_LEN, ITEM_ID_LEN,
    NONCE_LEN, ROOT_SECRET_LEN,
};
pub use metadata::{
    PrivateDataProtectionMetadata, ProtectedConstantRecord, PRIVATE_METADATA_SCHEMA,
};
pub use resource::{
    build_resource_bundle, normalize_resource_path, ProtectedResourceRecord, ResourceBundle,
    ResourceBundleBuild, ResourceDecision, ResourceInput, ResourceSelector,
};
pub use runtime::{CachePolicy, DecryptRuntime, SensitiveBytes, SensitiveString};
pub use sensitivity::{
    protect_string, ProtectedString, ProtectedStringRecord, Sensitivity, SensitivityDecision,
    StringCandidate, StringContext, StringSensitivityModel,
};
