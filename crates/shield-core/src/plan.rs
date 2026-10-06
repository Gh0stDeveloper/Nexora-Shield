use crate::error::{CoreError, Result};
use crate::ProtectionProfile;
use nexora_shield_package::ApkInspection;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Immutable execution plan generated before an APK is modified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildPlan {
    pub build_id: String,
    pub schema_version: u32,
    pub profile: ProtectionProfile,
    pub input: PathBuf,
    pub output: PathBuf,
    pub input_sha256: String,
    pub created_unix_ms: u128,
    pub align: bool,
    pub sign: bool,
    pub expected_dex_count: usize,
}

impl BuildPlan {
    /// Freezes the build inputs before any artifact mutation occurs.
    ///
    /// # Errors
    ///
    /// Returns an error when input/output paths are identical or a stable
    /// creation timestamp cannot be obtained.
    pub fn create(
        input: &Path,
        output: &Path,
        profile: ProtectionProfile,
        inspection: &ApkInspection,
        align: bool,
        sign: bool,
    ) -> Result<Self> {
        if input == output {
            return Err(CoreError::InvalidRequest(
                "input and output paths must be different".into(),
            ));
        }

        let created_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| CoreError::Clock(error.to_string()))?
            .as_millis();

        let prefix = inspection
            .sha256
            .get(..12)
            .unwrap_or(inspection.sha256.as_str());
        let build_id = format!("A-{prefix}-{created_unix_ms:x}");

        Ok(Self {
            build_id,
            schema_version: crate::CONFIG_SCHEMA_VERSION,
            profile,
            input: input.to_path_buf(),
            output: output.to_path_buf(),
            input_sha256: inspection.sha256.clone(),
            created_unix_ms,
            align,
            sign,
            expected_dex_count: inspection.dex_files.len(),
        })
    }
}
