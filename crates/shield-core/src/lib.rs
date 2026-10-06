//! Foundational contracts for Nexora Shield.
//!
//! Phase 0 intentionally keeps this crate small. Packaging, DEX processing,
//! cryptography, RASP and VM functionality are introduced in later phases.

#![forbid(unsafe_code)]

use core::fmt;
use core::str::FromStr;

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
    /// Stable configuration name for this profile.
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

    fn from_str(value: &str) -> Result<Self, Self::Err> {
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
