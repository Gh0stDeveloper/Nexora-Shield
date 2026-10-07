use crate::error::{ReleaseError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

pub const PUBLIC_API_CONTRACT_VERSION: u32 = 1;
pub const STABLE_CONFIG_SCHEMA: u32 = 1;
pub const MINIMUM_ANDROID_SDK: u32 = 24;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiSurface {
    pub contract_version: u32,
    pub config_schema: u32,
    pub minimum_android_sdk: u32,
    pub gradle_plugin_id: String,
    pub cli_commands: Vec<String>,
    pub protection_profiles: Vec<String>,
    pub artifact_types: Vec<String>,
}

impl ApiSurface {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        let contract: Self = serde_json::from_slice(&bytes)?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn validate(&self) -> Result<()> {
        if self.contract_version != PUBLIC_API_CONTRACT_VERSION {
            return Err(ReleaseError::InvalidApiContract(format!(
                "contract version must be {PUBLIC_API_CONTRACT_VERSION}"
            )));
        }
        if self.config_schema != STABLE_CONFIG_SCHEMA {
            return Err(ReleaseError::InvalidApiContract(format!(
                "config schema must remain {STABLE_CONFIG_SCHEMA} for 1.0"
            )));
        }
        if self.minimum_android_sdk != MINIMUM_ANDROID_SDK {
            return Err(ReleaseError::InvalidApiContract(format!(
                "minimum Android SDK must remain {MINIMUM_ANDROID_SDK} for 1.0"
            )));
        }
        if self.gradle_plugin_id != "dev.nexora.shield" {
            return Err(ReleaseError::InvalidApiContract(
                "Gradle plugin id changed after API freeze".into(),
            ));
        }

        validate_unique("CLI command", &self.cli_commands)?;
        validate_unique("profile", &self.protection_profiles)?;
        validate_unique("artifact type", &self.artifact_types)?;

        let required_profiles = BTreeSet::from([
            "standard".to_owned(),
            "hardened".to_owned(),
            "maximum".to_owned(),
        ]);
        let profiles = self
            .protection_profiles
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if profiles != required_profiles {
            return Err(ReleaseError::InvalidApiContract(
                "1.0 protection profiles must be standard, hardened and maximum".into(),
            ));
        }

        for required in ["protect", "inspect", "verify", "profiles"] {
            if !self.cli_commands.iter().any(|command| command == required) {
                return Err(ReleaseError::InvalidApiContract(format!(
                    "required CLI command '{required}' is missing"
                )));
            }
        }
        Ok(())
    }
}

fn validate_unique(kind: &str, values: &[String]) -> Result<()> {
    if values.is_empty() {
        return Err(ReleaseError::InvalidApiContract(format!(
            "{kind} list must not be empty"
        )));
    }

    let mut seen = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() {
            return Err(ReleaseError::InvalidApiContract(format!(
                "{kind} must not be blank"
            )));
        }
        if !seen.insert(value) {
            return Err(ReleaseError::InvalidApiContract(format!(
                "duplicate {kind} '{value}'"
            )));
        }
    }
    Ok(())
}
