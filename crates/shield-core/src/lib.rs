//! Core orchestration contracts for Nexora Shield.
//!
//! Phase A adds immutable build planning, transactional APK packaging and
//! public/private build reports. DEX transformations start in Phase B.

#![forbid(unsafe_code)]

mod dex_preflight;
mod dex_selection;
mod dex_stage;
mod error;
mod pipeline;
mod plan;
mod policy;
mod production;
mod report;

use core::fmt;
use core::str::FromStr;

pub use dex_preflight::{DexPreflight, DexUnitPreflight, MAX_DEX_BYTES, MAX_TOTAL_DEX_BYTES};
pub use dex_selection::{DexSelectorPolicy, MAX_DEX_SELECTOR_RULES};
pub use dex_stage::StagedDexResult;
pub use error::{CoreError, Result};
pub use pipeline::{protect_apk, PipelineResult, PipelineStage, ProtectionRequest};
pub use plan::BuildPlan;
pub use policy::{EffectiveProductionPolicy, ProductionControl, ProductionOverrides};
pub use production::{
    protect_production_apk, protect_production_apk_with_overrides,
    protect_production_apk_with_selection, PlannedStage,
    ProductionBuildContext, ProductionStage, StageIntegration, StageRequirement,
};
pub use report::{apk_inspection_json, write_report_atomic, PrivateBuildReport, PublicBuildReport};

/// Current configuration schema supported by the foundation.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Protection profiles exposed by the public configuration contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectionProfile {
    /// Baseline hardening with conservative runtime cost.
    Standard,
    /// Multi-layer hardening intended for production applications.
    Hardened,
    /// Selective maximum-strength hardening for high-value code paths.
    Maximum,
}

impl ProtectionProfile {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Hardened => "hardened",
            Self::Maximum => "maximum",
        }
    }
}

impl fmt::Display for ProtectionProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Error returned when a profile name is not part of the stable contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseProtectionProfileError;

impl fmt::Display for ParseProtectionProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown Nexora Shield protection profile")
    }
}

impl std::error::Error for ParseProtectionProfileError {}

impl FromStr for ProtectionProfile {
    type Err = ParseProtectionProfileError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "standard" => Ok(Self::Standard),
            "hardened" => Ok(Self::Hardened),
            "maximum" => Ok(Self::Maximum),
            _ => Err(ParseProtectionProfileError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ProtectionProfile, CONFIG_SCHEMA_VERSION};

    #[test]
    fn schema_starts_at_one() {
        assert_eq!(CONFIG_SCHEMA_VERSION, 1);
    }

    #[test]
    fn profiles_have_stable_names() {
        assert_eq!(ProtectionProfile::Standard.as_str(), "standard");
        assert_eq!(ProtectionProfile::Hardened.as_str(), "hardened");
        assert_eq!(ProtectionProfile::Maximum.as_str(), "maximum");
    }

    #[test]
    fn profile_parser_accepts_only_contract_values() {
        assert_eq!(
            "hardened".parse::<ProtectionProfile>(),
            Ok(ProtectionProfile::Hardened)
        );
        assert!("aggressive".parse::<ProtectionProfile>().is_err());
    }
}
