use crate::signal::{
    EvidenceStrength, RaspSignal, SignalCategory, SignalSet, SignalSeverity, SignalSource,
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DebugObservation {
    pub application_debuggable: bool,
    pub debugger_connected: bool,
    pub waiting_for_debugger: bool,
    pub jdwp_transport_active: bool,
    pub tracer_pid: Option<u32>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DebugEvaluator;

impl DebugEvaluator {
    #[must_use]
    pub fn evaluate(observation: &DebugObservation) -> SignalSet {
        let mut signals = SignalSet::default();

        if observation.application_debuggable {
            signals.push(RaspSignal::new(
                "debug.application_debuggable",
                SignalCategory::Debug,
                SignalSeverity::Info,
                EvidenceStrength::Weak,
                SignalSource::AndroidRuntime,
                "application reports a debuggable runtime configuration",
            ));
        }

        if observation.debugger_connected {
            signals.push(RaspSignal::new(
                "debug.debugger_connected",
                SignalCategory::Debug,
                SignalSeverity::High,
                EvidenceStrength::Strong,
                SignalSource::AndroidRuntime,
                "a debugger connection is currently observable",
            ));
        }

        if observation.waiting_for_debugger {
            signals.push(RaspSignal::new(
                "debug.waiting_for_debugger",
                SignalCategory::Debug,
                SignalSeverity::Medium,
                EvidenceStrength::Moderate,
                SignalSource::AndroidRuntime,
                "runtime is waiting for a debugger",
            ));
        }

        if observation.jdwp_transport_active {
            signals.push(RaspSignal::new(
                "debug.jdwp_transport_active",
                SignalCategory::Debug,
                SignalSeverity::Medium,
                EvidenceStrength::Moderate,
                SignalSource::AndroidRuntime,
                "JDWP transport is observable",
            ));
        }

        if let Some(tracer_pid) = observation.tracer_pid {
            if tracer_pid != 0 {
                signals.push(
                    RaspSignal::new(
                        "debug.tracer_present",
                        SignalCategory::Debug,
                        SignalSeverity::Critical,
                        EvidenceStrength::Definitive,
                        SignalSource::LinuxProcfs,
                        "the process reports a non-zero tracer PID",
                    )
                    .with_detail("tracer_pid", tracer_pid.to_string()),
                );
            }
        }

        signals
    }
}
