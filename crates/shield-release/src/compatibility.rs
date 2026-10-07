use crate::error::{ReleaseError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompatibilityMatrix {
    pub schema: u32,
    pub rust_msrv: String,
    pub minimum_android_sdk: u32,
    pub jdk: String,
    pub gradle: String,
    pub android_gradle_plugin: String,
    pub android_abis: Vec<String>,
    pub artifact_types: Vec<String>,
    pub desktop_operating_systems: Vec<String>,
}

impl CompatibilityMatrix {
    pub fn load(path: &Path) -> Result<Self> {
        let value: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 {
            return Err(ReleaseError::InvalidCompatibility(
                "compatibility matrix schema must be 1".into(),
            ));
        }
        if self.rust_msrv != "1.81" {
            return Err(ReleaseError::InvalidCompatibility(
                "1.0 MSRV must remain Rust 1.81".into(),
            ));
        }
        if self.minimum_android_sdk != 24 {
            return Err(ReleaseError::InvalidCompatibility(
                "1.0 minimum Android SDK must remain 24".into(),
            ));
        }
        if self.jdk != "17" {
            return Err(ReleaseError::InvalidCompatibility(
                "Gradle plugin release requires JDK 17".into(),
            ));
        }
        require_values(
            "Android ABI",
            &self.android_abis,
            &["arm64-v8a", "x86_64"],
        )?;
        require_values(
            "artifact type",
            &self.artifact_types,
            &["apk", "aab", "aar", "apks"],
        )?;
        require_values(
            "desktop OS",
            &self.desktop_operating_systems,
            &["linux", "macos", "windows"],
        )?;
        Ok(())
    }
}

fn require_values(kind: &str, actual: &[String], required: &[&str]) -> Result<()> {
    let set = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    for value in required {
        if !set.contains(value) {
            return Err(ReleaseError::InvalidCompatibility(format!(
                "required {kind} '{value}' is missing"
            )));
        }
    }
    Ok(())
}
