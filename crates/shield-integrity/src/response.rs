use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegritySeverity {
    Info,
    Warning,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityResponse {
    Continue,
    Report,
    RequireReverification,
    DenySensitiveOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponsePolicy {
    pub warning_response: IntegrityResponse,
    pub high_response: IntegrityResponse,
    pub critical_response: IntegrityResponse,
}

impl Default for ResponsePolicy {
    fn default() -> Self {
        Self {
            warning_response: IntegrityResponse::Report,
            high_response: IntegrityResponse::RequireReverification,
            critical_response: IntegrityResponse::DenySensitiveOperation,
        }
    }
}

impl ResponsePolicy {
    #[must_use]
    pub const fn response_for(&self, severity: IntegritySeverity) -> IntegrityResponse {
        match severity {
            IntegritySeverity::Info => IntegrityResponse::Continue,
            IntegritySeverity::Warning => self.warning_response,
            IntegritySeverity::High => self.high_response,
            IntegritySeverity::Critical => self.critical_response,
        }
    }
}
