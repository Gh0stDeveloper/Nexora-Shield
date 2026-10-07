use crate::server::AttestationRequest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyDataCategory {
    ApplicationId,
    BuildId,
    FeatureName,
    NormalizedRisk,
    ProviderId,
    OpaqueAttestationToken,
    SessionChallenge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyAuditReport {
    pub categories: BTreeSet<PrivacyDataCategory>,
    pub raw_attestation_token_bytes: usize,
    pub free_form_device_metadata_fields: usize,
    pub stable_device_identifier_fields: usize,
}

impl PrivacyAuditReport {
    #[must_use]
    pub fn uses_minimal_request_shape(&self) -> bool {
        self.free_form_device_metadata_fields == 0 && self.stable_device_identifier_fields == 0
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PrivacyAudit;

impl PrivacyAudit {
    #[must_use]
    pub fn inspect_request(request: &AttestationRequest) -> PrivacyAuditReport {
        let categories = BTreeSet::from([
            PrivacyDataCategory::ApplicationId,
            PrivacyDataCategory::BuildId,
            PrivacyDataCategory::FeatureName,
            PrivacyDataCategory::NormalizedRisk,
            PrivacyDataCategory::ProviderId,
            PrivacyDataCategory::OpaqueAttestationToken,
            PrivacyDataCategory::SessionChallenge,
        ]);

        PrivacyAuditReport {
            categories,
            raw_attestation_token_bytes: request.evidence.token.len(),
            free_form_device_metadata_fields: 0,
            stable_device_identifier_fields: 0,
        }
    }
}
