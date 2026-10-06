use crate::container::{seal, ContainerKind};
use crate::error::{DataProtectionError, Result};
use crate::key::{hex_lower, KeySchedule};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    Internal,
    Sensitive,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringContext {
    General,
    Endpoint,
    Authentication,
    Configuration,
    CertificatePin,
    License,
}

#[derive(Clone, PartialEq, Eq)]
pub struct StringCandidate {
    pub logical_id: String,
    pub value: String,
    pub context: StringContext,
}

impl fmt::Debug for StringCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StringCandidate")
            .field("logical_id", &self.logical_id)
            .field("value", &"[REDACTED]")
            .field("value_len", &self.value.len())
            .field("context", &self.context)
            .finish()
    }
}

impl StringCandidate {
    #[must_use]
    pub fn new(
        logical_id: impl Into<String>,
        value: impl Into<String>,
        context: StringContext,
    ) -> Self {
        Self {
            logical_id: logical_id.into(),
            value: value.into(),
            context,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensitivityDecision {
    pub sensitivity: Sensitivity,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringSensitivityModel {
    pub minimum_length: usize,
    pub threshold: Sensitivity,
    force_protect: BTreeSet<String>,
    force_public: BTreeSet<String>,
}

impl Default for StringSensitivityModel {
    fn default() -> Self {
        Self {
            minimum_length: 4,
            threshold: Sensitivity::Sensitive,
            force_protect: BTreeSet::new(),
            force_public: BTreeSet::new(),
        }
    }
}

impl StringSensitivityModel {
    pub fn force_protect(&mut self, logical_id: impl Into<String>) {
        self.force_protect.insert(logical_id.into());
    }

    pub fn force_public(&mut self, logical_id: impl Into<String>) {
        self.force_public.insert(logical_id.into());
    }

    #[must_use]
    pub fn classify(&self, candidate: &StringCandidate) -> SensitivityDecision {
        if self.force_public.contains(&candidate.logical_id) {
            return SensitivityDecision {
                sensitivity: Sensitivity::Public,
                reasons: vec!["explicit public override".into()],
            };
        }
        if self.force_protect.contains(&candidate.logical_id) {
            return SensitivityDecision {
                sensitivity: Sensitivity::Critical,
                reasons: vec!["explicit protect override".into()],
            };
        }

        let trimmed = candidate.value.trim();
        if trimmed.len() < self.minimum_length || looks_like_runtime_contract(trimmed) {
            return SensitivityDecision {
                sensitivity: Sensitivity::Public,
                reasons: vec!["short or runtime-contract string".into()],
            };
        }

        let lower = trimmed.to_ascii_lowercase();
        let mut sensitivity = context_floor(candidate.context);
        let mut reasons = Vec::new();

        for indicator in CRITICAL_INDICATORS {
            if lower.contains(indicator) {
                sensitivity = sensitivity.max(Sensitivity::Critical);
                reasons.push(format!("critical indicator: {indicator}"));
            }
        }

        for indicator in SENSITIVE_INDICATORS {
            if lower.contains(indicator) {
                sensitivity = sensitivity.max(Sensitivity::Sensitive);
                reasons.push(format!("sensitive indicator: {indicator}"));
            }
        }

        if looks_like_url(trimmed) {
            sensitivity = sensitivity.max(Sensitivity::Sensitive);
            reasons.push("network endpoint".into());
        }

        if reasons.is_empty() && sensitivity == Sensitivity::Public {
            sensitivity = Sensitivity::Internal;
            reasons.push("non-contract application literal".into());
        }

        SensitivityDecision {
            sensitivity,
            reasons,
        }
    }

    #[must_use]
    pub fn should_protect(&self, decision: &SensitivityDecision) -> bool {
        decision.sensitivity >= self.threshold
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedStringRecord {
    pub logical_id: String,
    pub opaque_id: String,
    pub sensitivity: Sensitivity,
    pub original_bytes: u64,
    pub protected_bytes: u64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedString {
    pub container: Vec<u8>,
    pub record: ProtectedStringRecord,
}

pub fn protect_string(
    schedule: &KeySchedule,
    model: &StringSensitivityModel,
    candidate: &StringCandidate,
) -> Result<Option<ProtectedString>> {
    if candidate.logical_id.is_empty() {
        return Err(DataProtectionError::KeyDerivation(
            "string logical identifier must not be empty".into(),
        ));
    }

    let decision = model.classify(candidate);
    if !model.should_protect(&decision) {
        return Ok(None);
    }

    let container = seal(
        schedule,
        ContainerKind::String,
        &candidate.logical_id,
        candidate.value.as_bytes(),
    )?;
    let opaque_id =
        schedule.opaque_item_id(crate::key::KeyDomain::String, &candidate.logical_id)?;

    Ok(Some(ProtectedString {
        record: ProtectedStringRecord {
            logical_id: candidate.logical_id.clone(),
            opaque_id: hex_lower(&opaque_id),
            sensitivity: decision.sensitivity,
            original_bytes: len_u64(candidate.value.len())?,
            protected_bytes: len_u64(container.len())?,
            reasons: decision.reasons,
        },
        container,
    }))
}

const CRITICAL_INDICATORS: &[&str] = &[
    "api_key",
    "apikey",
    "client_secret",
    "private_key",
    "authorization:",
    "bearer ",
    "password",
    "passwd",
    "access_token",
    "refresh_token",
    "certificatepin",
    "sha256/",
];

const SENSITIVE_INDICATORS: &[&str] = &[
    "oauth", "session", "license", "billing", "webhook", "endpoint", "secret", "token",
];

const fn context_floor(context: StringContext) -> Sensitivity {
    match context {
        StringContext::General => Sensitivity::Public,
        StringContext::Endpoint | StringContext::Configuration | StringContext::License => {
            Sensitivity::Sensitive
        }
        StringContext::Authentication | StringContext::CertificatePin => Sensitivity::Critical,
    }
}

fn looks_like_url(value: &str) -> bool {
    value.starts_with("https://") || value.starts_with("http://") || value.starts_with("wss://")
}

fn looks_like_runtime_contract(value: &str) -> bool {
    value.starts_with('L') && value.ends_with(';')
        || matches!(
            value,
            "<init>"
                | "<clinit>"
                | "onCreate"
                | "onStart"
                | "onResume"
                | "onPause"
                | "onStop"
                | "onDestroy"
        )
}

fn len_u64(value: usize) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| DataProtectionError::InvalidContainer("length does not fit u64".into()))
}
