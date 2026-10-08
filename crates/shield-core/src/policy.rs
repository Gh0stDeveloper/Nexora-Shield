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
    const fn mask(self) -> u8 {
        match self {
            Self::DataProtection => 1,
            Self::NativeShield => 2,
            Self::VmShield => 4,
            Self::Diversity => 8,
            Self::IntegrityGraph => 16,
            Self::RaspRuntime => 32,
            Self::Attestation => 64,
        }
    }

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
    enabled_mask: u8,
}

impl EffectiveProductionPolicy {
    /// Resolve profile requirements and operator overrides, failing closed for downgrade attempts.
    ///
    /// # Errors
    ///
    /// Returns an error when an explicit override disables a mandatory control.
    pub fn resolve(profile: ProtectionProfile, overrides: &ProductionOverrides) -> Result<Self> {
        use ProductionControl as C;
        let hardened = profile != ProtectionProfile::Standard;
        let maximum = profile == ProtectionProfile::Maximum;
        let selections = [
            (C::DataProtection, hardened, overrides.data_protection),
            (C::NativeShield, maximum, overrides.native_shield),
            (C::VmShield, maximum, overrides.vm_shield),
            (C::Diversity, hardened, overrides.diversity),
            (C::IntegrityGraph, true, overrides.integrity_graph),
            (C::RaspRuntime, hardened, overrides.rasp_runtime),
            (C::Attestation, false, overrides.attestation),
        ];
        let mut enabled_mask = 0_u8;
        for (control, mandatory, override_value) in selections {
            if resolve_control(control.as_str(), mandatory, override_value)? {
                enabled_mask |= control.mask();
            }
        }
        Ok(Self {
            profile,
            enabled_mask,
        })
    }

    #[must_use]
    pub const fn enabled(self, control: ProductionControl) -> bool {
        self.enabled_mask & control.mask() != 0
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
        assert!(standard.enabled(C::IntegrityGraph));
        assert!(!standard.enabled(C::DataProtection) && !standard.enabled(C::NativeShield) && !standard.enabled(C::VmShield));
        assert!(!standard.enabled(C::Diversity) && !standard.enabled(C::RaspRuntime) && !standard.enabled(C::Attestation));
        assert!(hardened.enabled(C::DataProtection) && hardened.enabled(C::Diversity) && hardened.enabled(C::RaspRuntime));
        assert!(!hardened.enabled(C::NativeShield) && !hardened.enabled(C::VmShield));
        assert!(maximum.enabled(C::NativeShield) && maximum.enabled(C::VmShield));
    }

    #[test]
    fn explicit_selection_is_required_even_in_standard_profile() {
        let mut overrides = O::default();
        assert!(overrides.set(C::VmShield, true).is_ok());
        assert!(overrides.set(C::Attestation, true).is_ok());
        let result = P::resolve(ProtectionProfile::Standard, &overrides);
        assert!(matches!(result, Ok(policy) if policy.enabled(C::VmShield) && policy.enabled(C::Attestation)));
    }

    #[test]
    fn attempts_to_downgrade_mandatory_controls_are_rejected() {
        for profile in [
            ProtectionProfile::Standard,
            ProtectionProfile::Hardened,
            ProtectionProfile::Maximum,
        ] {
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
