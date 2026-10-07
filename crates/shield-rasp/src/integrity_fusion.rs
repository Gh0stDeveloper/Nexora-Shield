use crate::signal::{
    EvidenceStrength, RaspSignal, SignalCategory, SignalSet, SignalSeverity, SignalSource,
};
use nexora_shield_integrity::{
    IntegrityFailureKind, IntegritySeverity, IntegrityVerdict,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct IntegritySignalFusion;

impl IntegritySignalFusion {
    #[must_use]
    pub fn from_verdict(verdict: &IntegrityVerdict) -> SignalSet {
        let mut signals = SignalSet::default();

        for failure in &verdict.failures {
            let kind = failure_kind_code(failure.kind);
            let strength = if failure.observed.is_some() {
                EvidenceStrength::Definitive
            } else {
                EvidenceStrength::Strong
            };

            signals.push(
                RaspSignal::new(
                    format!("integrity.{kind}"),
                    SignalCategory::Integrity,
                    map_severity(failure.severity),
                    strength,
                    SignalSource::IntegrityEngine,
                    "integrity verification reported a protected-state mismatch",
                )
                .with_detail("failure_kind", kind)
                .with_detail("node_label", failure.label.clone()),
            );
        }

        signals
    }
}

const fn map_severity(severity: IntegritySeverity) -> SignalSeverity {
    match severity {
        IntegritySeverity::Info => SignalSeverity::Info,
        IntegritySeverity::Warning => SignalSeverity::Low,
        IntegritySeverity::High => SignalSeverity::High,
        IntegritySeverity::Critical => SignalSeverity::Critical,
    }
}

const fn failure_kind_code(kind: IntegrityFailureKind) -> &'static str {
    match kind {
        IntegrityFailureKind::Certificate => "certificate",
        IntegrityFailureKind::Package => "package",
        IntegrityFailureKind::MissingDex => "missing_dex",
        IntegrityFailureKind::DexFile => "dex_file",
        IntegrityFailureKind::DexRegion => "dex_region",
        IntegrityFailureKind::MissingArtifact => "missing_artifact",
        IntegrityFailureKind::Resource => "resource",
        IntegrityFailureKind::Native => "native",
    }
}
