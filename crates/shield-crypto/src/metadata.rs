use crate::benchmark::ExposureReport;
use crate::error::{DataProtectionError, Result};
use crate::resource::ProtectedResourceRecord;
use crate::sensitivity::ProtectedStringRecord;
use serde::{Deserialize, Serialize};

pub const PRIVATE_METADATA_SCHEMA: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedConstantRecord {
    pub logical_id: String,
    pub opaque_id: String,
    pub original_bytes: u64,
    pub protected_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivateDataProtectionMetadata {
    pub schema: u32,
    pub application_id: String,
    pub build_id: String,
    pub context_fingerprint: String,
    pub strings: Vec<ProtectedStringRecord>,
    pub constants: Vec<ProtectedConstantRecord>,
    pub resources: Vec<ProtectedResourceRecord>,
    pub exposure: Option<ExposureReport>,
}

impl PrivateDataProtectionMetadata {
    #[must_use]
    pub fn new(
        application_id: impl Into<String>,
        build_id: impl Into<String>,
        context_fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            schema: PRIVATE_METADATA_SCHEMA,
            application_id: application_id.into(),
            build_id: build_id.into(),
            context_fingerprint: context_fingerprint.into(),
            strings: Vec::new(),
            constants: Vec::new(),
            resources: Vec::new(),
            exposure: None,
        }
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|error| DataProtectionError::Metadata(error.to_string()))
    }

    pub fn from_json(value: &str) -> Result<Self> {
        let metadata: Self = serde_json::from_str(value)
            .map_err(|error| DataProtectionError::Metadata(error.to_string()))?;
        if metadata.schema != PRIVATE_METADATA_SCHEMA {
            return Err(DataProtectionError::Metadata(format!(
                "unsupported private metadata schema {}",
                metadata.schema
            )));
        }
        Ok(metadata)
    }
}
