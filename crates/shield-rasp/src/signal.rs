use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalCategory {
    Debug,
    Instrumentation,
    HookInjection,
    ModifiedSystem,
    Emulator,
    Integrity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrength {
    Weak,
    Moderate,
    Strong,
    Definitive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalSource {
    AndroidRuntime,
    LinuxProcfs,
    NativeRuntime,
    IntegrityEngine,
    Application,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaspSignal {
    pub code: String,
    pub category: SignalCategory,
    pub severity: SignalSeverity,
    pub strength: EvidenceStrength,
    pub source: SignalSource,
    pub summary: String,
    pub details: BTreeMap<String, String>,
}

impl RaspSignal {
    #[must_use]
    pub fn new(
        code: impl Into<String>,
        category: SignalCategory,
        severity: SignalSeverity,
        strength: EvidenceStrength,
        source: SignalSource,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            category,
            severity,
            strength,
            source,
            summary: summary.into(),
            details: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalSet {
    signals: Vec<RaspSignal>,
}

impl SignalSet {
    pub fn push(&mut self, signal: RaspSignal) -> bool {
        let duplicate = self.signals.iter().any(|existing| {
            existing.code == signal.code
                && existing.source == signal.source
                && existing.details == signal.details
        });
        if duplicate {
            false
        } else {
            self.signals.push(signal);
            true
        }
    }

    pub fn extend(&mut self, signals: impl IntoIterator<Item = RaspSignal>) {
        for signal in signals {
            self.push(signal);
        }
    }

    #[must_use]
    pub fn signals(&self) -> &[RaspSignal] {
        &self.signals
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.signals.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signals.is_empty()
    }

    #[must_use]
    pub fn categories(&self) -> BTreeSet<SignalCategory> {
        self.signals.iter().map(|signal| signal.category).collect()
    }

    #[must_use]
    pub fn maximum_severity(&self) -> SignalSeverity {
        self.signals
            .iter()
            .map(|signal| signal.severity)
            .max()
            .unwrap_or(SignalSeverity::Info)
    }
}
