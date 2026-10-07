use crate::signal::{
    EvidenceStrength, RaspSignal, SignalCategory, SignalSet, SignalSeverity, SignalSource,
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct InstrumentationObservation {
    pub runtime_agent_present: bool,
    pub instrumentation_bridge_present: bool,
    pub unexpected_class_loader: bool,
    pub method_dispatch_changed: bool,
    pub loaded_agent_count: u16,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct InstrumentationEvaluator;

impl InstrumentationEvaluator {
    #[must_use]
    pub fn evaluate(observation: &InstrumentationObservation) -> SignalSet {
        let mut signals = SignalSet::default();

        if observation.runtime_agent_present {
            signals.push(RaspSignal::new(
                "instrumentation.runtime_agent_present",
                SignalCategory::Instrumentation,
                SignalSeverity::High,
                EvidenceStrength::Strong,
                SignalSource::AndroidRuntime,
                "an unexpected runtime instrumentation agent is observable",
            ));
        }

        if observation.instrumentation_bridge_present {
            signals.push(RaspSignal::new(
                "instrumentation.bridge_present",
                SignalCategory::Instrumentation,
                SignalSeverity::High,
                EvidenceStrength::Strong,
                SignalSource::AndroidRuntime,
                "an instrumentation bridge is observable in the process",
            ));
        }

        if observation.unexpected_class_loader {
            signals.push(RaspSignal::new(
                "instrumentation.unexpected_class_loader",
                SignalCategory::Instrumentation,
                SignalSeverity::Medium,
                EvidenceStrength::Moderate,
                SignalSource::AndroidRuntime,
                "an unexpected runtime class loader was observed",
            ));
        }

        if observation.method_dispatch_changed {
            signals.push(RaspSignal::new(
                "instrumentation.method_dispatch_changed",
                SignalCategory::Instrumentation,
                SignalSeverity::Critical,
                EvidenceStrength::Definitive,
                SignalSource::AndroidRuntime,
                "method dispatch differs from the protected runtime expectation",
            ));
        }

        if observation.loaded_agent_count > 0 {
            signals.push(
                RaspSignal::new(
                    "instrumentation.loaded_agent_count",
                    SignalCategory::Instrumentation,
                    SignalSeverity::Medium,
                    EvidenceStrength::Moderate,
                    SignalSource::Application,
                    "one or more runtime agents were reported",
                )
                .with_detail("count", observation.loaded_agent_count.to_string()),
            );
        }

        signals
    }
}
