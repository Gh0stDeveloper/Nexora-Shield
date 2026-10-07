use crate::error::{DiversityError, Result};
use crate::seed::{DiversityDomain, SeedDeriver};
use nexora_shield_vm::OpcodeAllocation;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmMapVariant {
    pub build_id: String,
    pub fingerprint: [u8; 32],
}

impl VmMapVariant {
    pub fn derive(
        seed: &SeedDeriver,
        build_id: &str,
    ) -> Result<(Self, OpcodeAllocation)> {
        if build_id.trim().is_empty() {
            return Err(DiversityError::EmptyBuildId);
        }
        let key = seed.domain_key(DiversityDomain::VmMap)?;
        let allocation = OpcodeAllocation::derive(build_id, &key)
            .map_err(|error| DiversityError::Vm(error.to_string()))?;
        let variant = Self {
            build_id: build_id.to_owned(),
            fingerprint: allocation.fingerprint(),
        };
        Ok((variant, allocation))
    }
}
