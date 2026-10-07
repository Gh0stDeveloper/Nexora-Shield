use crate::signal::{
    EvidenceStrength, RaspSignal, SignalCategory, SignalSet, SignalSeverity, SignalSource,
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmulatorObservation {
    pub generic_build_profile: bool,
    pub emulator_device_profile: bool,
    pub qemu_transport_present: bool,
    pub hypervisor_artifact_present: bool,
    pub sparse_sensor_profile: bool,
    pub missing_telephony_profile: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct EmulatorEvaluator;

impl EmulatorEvaluator {
    #[must_use]
    pub fn evaluate(observation: &EmulatorObservation) -> SignalSet {
        let mut signals = SignalSet::default();

        if observation.generic_build_profile {
            signals.push(RaspSignal::new(
                "emulator.generic_build_profile",
                SignalCategory::Emulator,
                SignalSeverity::Low,
                EvidenceStrength::Weak,
                SignalSource::AndroidRuntime,
                "the runtime build profile is generic",
            ));
        }

        if observation.emulator_device_profile {
            signals.push(RaspSignal::new(
                "emulator.device_profile",
                SignalCategory::Emulator,
                SignalSeverity::Medium,
                EvidenceStrength::Moderate,
                SignalSource::AndroidRuntime,
                "the device profile is consistent with a virtualized environment",
            ));
        }

        if observation.qemu_transport_present {
            signals.push(RaspSignal::new(
                "emulator.qemu_transport_present",
                SignalCategory::Emulator,
                SignalSeverity::High,
                EvidenceStrength::Strong,
                SignalSource::LinuxProcfs,
                "QEMU transport evidence was reported",
            ));
        }

        if observation.hypervisor_artifact_present {
            signals.push(RaspSignal::new(
                "emulator.hypervisor_artifact_present",
                SignalCategory::Emulator,
                SignalSeverity::Medium,
                EvidenceStrength::Moderate,
                SignalSource::NativeRuntime,
                "a hypervisor-related runtime artifact was reported",
            ));
        }

        if observation.sparse_sensor_profile {
            signals.push(RaspSignal::new(
                "emulator.sparse_sensor_profile",
                SignalCategory::Emulator,
                SignalSeverity::Low,
                EvidenceStrength::Weak,
                SignalSource::AndroidRuntime,
                "the sensor profile is unusually sparse",
            ));
        }

        if observation.missing_telephony_profile {
            signals.push(RaspSignal::new(
                "emulator.missing_telephony_profile",
                SignalCategory::Emulator,
                SignalSeverity::Low,
                EvidenceStrength::Weak,
                SignalSource::AndroidRuntime,
                "telephony characteristics expected by the application profile are absent",
            ));
        }

        signals
    }
}
