//! Resolved, immutable production policy; no artifact or secret material is created.
//! CLI overrides are typed. A selected control becomes required, never best-effort.

use crate::{CoreError, ProtectionProfile, Result};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionControl {
    DataProtection,
    NativeShield,
    VmShield,
    Diversity,
    IntegrityGraph,
    RaspRuntime,
    Attestation,
}

impl ProductionControl {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DataProtection => "data-protection",
            Self::NativeShield => "native-shield",
            Self::VmShield => "vm-shield",
            Self::Diversity => "diversity",
            Self::IntegrityGraph => "integrity-graph",
            Self::RaspRuntime => "rasp-runtime",
            Self::Attestation => "attestation",
        }
    }
}

impl FromStr for ProductionControl {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "data-protection" => Ok(Self::DataProtection),
            "native-shield" => Ok(Self::NativeShield),
            "vm-shield" => Ok(Self::VmShield),
            "diversity" => Ok(Self::Diversity),
            "integrity-graph" => Ok(Self::IntegrityGraph),
            "rasp-runtime" => Ok(Self::RaspRuntime),
            "attestation" => Ok(Self::Attestation),
            _ => Err(CoreError::InvalidRequest(format!(
                "unknown production control '{value}'"
            ))),
        }
    }
}

/// Explicit overrides only; None means apply the documented profile default.
/// Do not represent environment secrets or key material in this structure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProductionOverrides {
    pub data_protection: Option<bool>,
    pub native_shield: Option<bool>,
    pub vm_shield: Option<bool>,
    pub diversity: Option<bool>,
    pub integrity_graph: Option<bool>,
    pub rasp_runtime: Option<bool>,
    pub attestation: Option<bool>,
}

impl ProductionOverrides {
    /// Reject contradictory or repeated CLI overrides rather than last-value-wins.
    ///
    /// # Errors
    ///
    /// Returns an error if the same control has already been specified.
    pub fn set(&mut self, control: ProductionControl, enabled: bool) -> Result<()> {
        let slot = match control {
            ProductionControl::DataProtection => &mut self.data_protection,
            ProductionControl::NativeShield => &mut self.native_shield,
            ProductionControl::VmShield => &mut self.vm_shield,
            ProductionControl::Diversity => &mut self.diversity,
            ProductionControl::IntegrityGraph => &mut self.integrity_graph,
            ProductionControl::RaspRuntime => &mut self.rasp_runtime,
            ProductionControl::Attestation => &mut self.attestation,
        };
        if slot.is_some() {
            return Err(CoreError::InvalidRequest(format!(
                "duplicate production control override '{}'",
                control.as_str()
            )));
        }
        *slot = Some(enabled);
        Ok(())
    }
}

/// Immutable effective selections, computed before APK parsing or any filesystem writes.
/// Mandatory defaults cannot be disabled by a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveProductionPolicy {
    pub profile: ProtectionProfile,
    pub data_protection: bool,
    pub native_shield: bool,
    pub vm_shield: bool,
    pub diversity: bool,
    pub integrity_graph: bool,
    pub rasp_runtime: bool,
    pub attestation: bool,
}

impl EffectiveProductionPolicy {
    /// Resolve profile requirements and operator overrides, failing closed for downgrade attempts.
    ///
    /// # Errors
    ///
    /// Returns an error when an explicit override disables a mandatory control.
    pub fn resolve(profile: ProtectionProfile, overrides: &ProductionOverrides) -> Result<Self> {
        let hardened = profile != ProtectionProfile::Standard;
        let maximum = profile == ProtectionProfile::Maximum;
        Ok(Self {
            profile,
            data_protection: resolve_control("data-protection", hardened, overrides.data_protection)?,
            native_shield: resolve_control("native-shield", maximum, overrides.native_shield)?,
            vm_shield: resolve_control("vm-shield", maximum, overrides.vm_shield)?,
            diversity: resolve_control("diversity", hardened, overrides.diversity)?,
            integrity_graph: resolve_control("integrity-graph", true, overrides.integrity_graph)?,
            rasp_runtime: resolve_control("rasp-runtime", hardened, overrides.rasp_runtime)?,
            attestation: resolve_control("attestation", false, overrides.attestation)?,
        })
    }

    #[must_use]
    pub const fn enabled(self, control: ProductionControl) -> bool {
        match control {
            ProductionControl::DataProtection => self.data_protection,
            ProductionControl::NativeShield => self.native_shield,
            ProductionControl::VmShield => self.vm_shield,
            ProductionControl::Diversity => self.diversity,
            ProductionControl::IntegrityGraph => self.integrity_graph,
            ProductionControl::RaspRuntime => self.rasp_runtime,
            ProductionControl::Attestation => self.attestation,
        }
    }
}

fn resolve_control(name: &str, mandatory: bool, override_value: Option<bool>) -> Result<bool> {
    if mandatory && override_value == Some(false) {
        return Err(CoreError::InvalidRequest(format!(
            "profile requires control '{name}'; disabling it is forbidden"
        )));
    }
    Ok(mandatory || override_value.unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::{EffectiveProductionPolicy as P, ProductionControl as C, ProductionOverrides as O};
    use crate::ProtectionProfile;

    #[test]
    fn documented_profile_defaults_are_resolved_before_execution() {
        let standard = P::resolve(ProtectionProfile::Standard, &O::default());
        let hardened = P::resolve(ProtectionProfile::Hardened, &O::default());
        let maximum = P::resolve(ProtectionProfile::Maximum, &O::default());
        assert!(standard.is_ok() && hardened.is_ok() && maximum.is_ok());
        let standard = standard.unwrap_or_else(|_| unreachable!());
        let hardened = hardened.unwrap_or_else(|_| unreachable!());
        let maximum = maximum.unwrap_or_else(|_| unreachable!());
        assert!(standard.integrity_graph);
        assert!(!standard.data_protection && !standard.native_shield && !standard.vm_shield);
        assert!(!standard.diversity && !standard.rasp_runtime && !standard.attestation);
        assert!(hardened.data_protection && hardened.diversity && hardened.rasp_runtime);
        assert!(!hardened.native_shield && !hardened.vm_shield);
        assert!(maximum.native_shield && maximum.vm_shield);
    }

    #[test]
    fn explicit_selection_is_required_even_in_standard_profile() {
        let mut overrides = O::default();
        assert!(overrides.set(C::VmShield, true).is_ok());
        assert!(overrides.set(C::Attestation, true).is_ok());
        let result = P::resolve(ProtectionProfile::Standard, &overrides);
        assert!(matches!(result, Ok(policy) if policy.vm_shield && policy.attestation));
    }

    #[test]
    fn attempts_to_downgrade_mandatory_controls_are_rejected() {
        for profile in [ProtectionProfile::Standard, ProtectionProfile::Hardened, ProtectionProfile::Maximum] {
            let mut overrides = O::default();
            assert!(overrides.set(C::IntegrityGraph, false).is_ok());
            assert!(P::resolve(profile, &overrides).is_err());
        }
        let mut overrides = O::default();
        assert!(overrides.set(C::RaspRuntime, false).is_ok());
        assert!(P::resolve(ProtectionProfile::Hardened, &overrides).is_err());
        let mut overrides = O::default();
        assert!(overrides.set(C::NativeShield, false).is_ok());
        assert!(P::resolve(ProtectionProfile::Maximum, &overrides).is_err());
    }

    #[test]
    fn duplicate_and_unknown_control_overrides_are_rejected() {
        let mut overrides = O::default();
        assert!(overrides.set(C::Diversity, true).is_ok());
        assert!(overrides.set(C::Diversity, false).is_err());
        assert!("native-shields".parse::<C>().is_err());
    }
}
