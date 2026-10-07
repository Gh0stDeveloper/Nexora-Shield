use crate::signal::{EvidenceStrength, SignalCategory, SignalSet, SignalSeverity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Clean,
    Observed,
    Elevated,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskThresholds {
    pub elevated: u32,
    pub high: u32,
    pub critical: u32,
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self {
            elevated: 20,
            high: 45,
            critical: 80,
        }
    }
}

impl RiskThresholds {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.elevated > 0 && self.elevated < self.high && self.high < self.critical
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskReason {
    WeightedEvidence,
    CrossCategoryCorrelation,
    CriticalDefinitiveEvidence,
    WeakEvidenceCap,
    ModerateEvidenceCap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub score: u32,
    pub level: RiskLevel,
    pub signals_evaluated: usize,
    pub categories: BTreeSet<SignalCategory>,
    pub maximum_signal_severity: SignalSeverity,
    pub strongest_evidence: EvidenceStrength,
    pub reasons: Vec<RiskReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiskEngine {
    thresholds: RiskThresholds,
}

impl Default for RiskEngine {
    fn default() -> Self {
        Self::new(RiskThresholds::default())
    }
}

impl RiskEngine {
    #[must_use]
    pub const fn new(thresholds: RiskThresholds) -> Self {
        Self { thresholds }
    }

    #[must_use]
    pub const fn thresholds(self) -> RiskThresholds {
        self.thresholds
    }

    #[must_use]
    pub fn evaluate(self, signals: &SignalSet) -> RiskAssessment {
        if signals.is_empty() {
            return RiskAssessment {
                score: 0,
                level: RiskLevel::Clean,
                signals_evaluated: 0,
                categories: BTreeSet::new(),
                maximum_signal_severity: SignalSeverity::Info,
                strongest_evidence: EvidenceStrength::Weak,
                reasons: Vec::new(),
            };
        }

        let categories = signals.categories();
        let maximum_signal_severity = signals.maximum_severity();
        let strongest_evidence = signals
            .signals()
            .iter()
            .map(|signal| signal.strength)
            .max()
            .unwrap_or(EvidenceStrength::Weak);

        let mut score = signals
            .signals()
            .iter()
            .map(|signal| signal_score(signal.severity, signal.strength))
            .fold(0_u32, u32::saturating_add);

        let mut reasons = vec![RiskReason::WeightedEvidence];

        if categories.len() > 1 && strongest_evidence >= EvidenceStrength::Strong {
            let correlated_categories = u32::try_from(categories.len().saturating_sub(1))
                .unwrap_or(u32::MAX);
            score = score.saturating_add(correlated_categories.saturating_mul(6));
            reasons.push(RiskReason::CrossCategoryCorrelation);
        }

        let has_critical_definitive = signals.signals().iter().any(|signal| {
            signal.severity == SignalSeverity::Critical
                && signal.strength == EvidenceStrength::Definitive
        });

        let mut level = level_for_score(score, self.thresholds);

        if has_critical_definitive {
            level = RiskLevel::Critical;
            reasons.push(RiskReason::CriticalDefinitiveEvidence);
        } else if strongest_evidence == EvidenceStrength::Weak && level > RiskLevel::Observed {
            level = RiskLevel::Observed;
            reasons.push(RiskReason::WeakEvidenceCap);
        } else if strongest_evidence <= EvidenceStrength::Moderate && level > RiskLevel::Elevated {
            level = RiskLevel::Elevated;
            reasons.push(RiskReason::ModerateEvidenceCap);
        }

        RiskAssessment {
            score,
            level,
            signals_evaluated: signals.len(),
            categories,
            maximum_signal_severity,
            strongest_evidence,
            reasons,
        }
    }
}

const fn level_for_score(score: u32, thresholds: RiskThresholds) -> RiskLevel {
    if score == 0 {
        RiskLevel::Clean
    } else if score >= thresholds.critical {
        RiskLevel::Critical
    } else if score >= thresholds.high {
        RiskLevel::High
    } else if score >= thresholds.elevated {
        RiskLevel::Elevated
    } else {
        RiskLevel::Observed
    }
}

const fn signal_score(severity: SignalSeverity, strength: EvidenceStrength) -> u32 {
    let severity_points: u32 = match severity {
        SignalSeverity::Info => 0,
        SignalSeverity::Low => 2,
        SignalSeverity::Medium => 6,
        SignalSeverity::High => 12,
        SignalSeverity::Critical => 20,
    };
    let strength_multiplier: u32 = match strength {
        EvidenceStrength::Weak => 1,
        EvidenceStrength::Moderate => 2,
        EvidenceStrength::Strong => 3,
        EvidenceStrength::Definitive => 4,
    };

    severity_points.saturating_mul(strength_multiplier)
}
