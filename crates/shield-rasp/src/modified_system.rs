use crate::signal::{
    EvidenceStrength, RaspSignal, SignalCategory, SignalSet, SignalSeverity, SignalSource,
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ModifiedSystemObservation {
    pub bootloader_unlocked: bool,
    pub verified_boot_not_green: bool,
    pub selinux_permissive: bool,
    pub system_partition_writable: bool,
    pub root_management_artifact_count: u16,
    pub privileged_binary_artifact_count: u16,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ModifiedSystemEvaluator;

impl ModifiedSystemEvaluator {
    #[must_use]
    pub fn evaluate(observation: &ModifiedSystemObservation) -> SignalSet {
        let mut signals = SignalSet::default();

        if observation.bootloader_unlocked {
            signals.push(RaspSignal::new(
                "system.bootloader_unlocked",
                SignalCategory::ModifiedSystem,
                SignalSeverity::Medium,
                EvidenceStrength::Moderate,
                SignalSource::AndroidRuntime,
                "the device reports an unlocked bootloader state",
            ));
        }

        if observation.verified_boot_not_green {
            signals.push(RaspSignal::new(
                "system.verified_boot_not_green",
                SignalCategory::ModifiedSystem,
                SignalSeverity::High,
                EvidenceStrength::Strong,
                SignalSource::AndroidRuntime,
                "verified boot is not in the expected green state",
            ));
        }

        if observation.selinux_permissive {
            signals.push(RaspSignal::new(
                "system.selinux_permissive",
                SignalCategory::ModifiedSystem,
                SignalSeverity::High,
                EvidenceStrength::Strong,
                SignalSource::LinuxProcfs,
                "SELinux is reported as permissive",
            ));
        }

        if observation.system_partition_writable {
            signals.push(RaspSignal::new(
                "system.system_partition_writable",
                SignalCategory::ModifiedSystem,
                SignalSeverity::High,
                EvidenceStrength::Strong,
                SignalSource::LinuxProcfs,
                "a protected system partition is reported writable",
            ));
        }

        if observation.root_management_artifact_count > 0 {
            signals.push(
                RaspSignal::new(
                    "system.root_management_artifacts",
                    SignalCategory::ModifiedSystem,
                    SignalSeverity::Medium,
                    EvidenceStrength::Moderate,
                    SignalSource::Application,
                    "root-management artifacts were reported",
                )
                .with_detail(
                    "count",
                    observation.root_management_artifact_count.to_string(),
                ),
            );
        }

        if observation.privileged_binary_artifact_count > 0 {
            signals.push(
                RaspSignal::new(
                    "system.privileged_binary_artifacts",
                    SignalCategory::ModifiedSystem,
                    SignalSeverity::Medium,
                    EvidenceStrength::Moderate,
                    SignalSource::Application,
                    "unexpected privileged-binary artifacts were reported",
                )
                .with_detail(
                    "count",
                    observation.privileged_binary_artifact_count.to_string(),
                ),
            );
        }

        signals
    }
}
