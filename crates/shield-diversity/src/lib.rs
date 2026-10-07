//! Nexora Shield Phase H per-build diversification.
//!
//! Diversity is deterministic only from explicit private build material. The
//! crate never treats diversity as cryptography or as a substitute for runtime
//! integrity, RASP or server-side authorization.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::similar_names
)]

mod cfg;
mod error;
mod integrity;
mod native;
mod pass;
mod regression;
mod rename;
mod seed;
mod strings;
mod vm;

pub use cfg::{CfgBranchVariant, CfgLayoutVariant, CfgVariantPlan};
pub use error::{DiversityError, Result};
pub use integrity::{IntegrityTopologyPlan, IntegrityTopologyVariant};
pub use native::NativeConstantVariant;
pub use pass::{DiversificationPass, PassVariantPlan};
pub use regression::{
    BuildDiversitySignature, BypassPortabilityReport, CrossBuildBypassRegression,
    DiversitySurface,
};
pub use rename::RenameVariant;
pub use seed::{
    BuildSeedContext, DiversityDomain, DiversityMode, PrivateBuildSeed, SeedDeriver,
};
pub use strings::{
    PublicStringShard, StringPartitionBuild, StringPartitionPlan, StringShard, StringShardEntry,
    StringShardLocation,
};
pub use vm::VmMapVariant;
