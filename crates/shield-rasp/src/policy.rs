use crate::response::RaspResponse;
use crate::risk::{RiskLevel, RiskThresholds};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySpec {
    pub thresholds: RiskThresholds,
    pub responses: BTreeMap<RiskLevel, RaspResponse>,
}

impl Default for PolicySpec {
    fn default() -> Self {
        let responses = BTreeMap::from([
            (RiskLevel::Clean, RaspResponse::Continue),
            (RiskLevel::Observed, RaspResponse::Continue),
            (RiskLevel::Elevated, RaspResponse::Report),
            (RiskLevel::High, RaspResponse::RequireReverification),
            (RiskLevel::Critical, RaspResponse::DenySensitiveOperation),
        ]);

        Self {
            thresholds: RiskThresholds::default(),
            responses,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledPolicy {
    thresholds: RiskThresholds,
    responses: BTreeMap<RiskLevel, RaspResponse>,
}

impl CompiledPolicy {
    pub fn compile(spec: PolicySpec) -> Result<Self, PolicyError> {
        if !spec.thresholds.is_valid() {
            return Err(PolicyError::InvalidThresholdOrder);
        }

        for level in [
            RiskLevel::Clean,
            RiskLevel::Observed,
            RiskLevel::Elevated,
            RiskLevel::High,
            RiskLevel::Critical,
        ] {
            if !spec.responses.contains_key(&level) {
                return Err(PolicyError::MissingResponse(level));
            }
        }

        let ordered = [
            RiskLevel::Clean,
            RiskLevel::Observed,
            RiskLevel::Elevated,
            RiskLevel::High,
            RiskLevel::Critical,
        ];
        for pair in ordered.windows(2) {
            let left = spec
                .responses
                .get(&pair[0])
                .copied()
                .ok_or(PolicyError::MissingResponse(pair[0]))?;
            let right = spec
                .responses
                .get(&pair[1])
                .copied()
                .ok_or(PolicyError::MissingResponse(pair[1]))?;
            if right < left {
                return Err(PolicyError::NonMonotonicResponse {
                    lower: pair[0],
                    higher: pair[1],
                });
            }
        }

        Ok(Self {
            thresholds: spec.thresholds,
            responses: spec.responses,
        })
    }

    #[must_use]
    pub const fn thresholds(&self) -> RiskThresholds {
        self.thresholds
    }

    #[must_use]
    pub fn response_for(&self, level: RiskLevel) -> RaspResponse {
        self.responses
            .get(&level)
            .copied()
            .unwrap_or(RaspResponse::DenySensitiveOperation)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    InvalidThresholdOrder,
    MissingResponse(RiskLevel),
    NonMonotonicResponse { lower: RiskLevel, higher: RiskLevel },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidThresholdOrder => {
                formatter.write_str("risk thresholds must be strictly increasing and non-zero")
            }
            Self::MissingResponse(level) => {
                write!(formatter, "policy is missing a response for {level:?}")
            }
            Self::NonMonotonicResponse { lower, higher } => write!(
                formatter,
                "policy response for {higher:?} is less restrictive than {lower:?}"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}
