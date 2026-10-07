use crate::signal::{
    EvidenceStrength, RaspSignal, SignalCategory, SignalSet, SignalSeverity, SignalSource,
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HookInjectionObservation {
    pub inline_hook_evidence: bool,
    pub import_table_redirect: bool,
    pub writable_executable_mapping: bool,
    pub code_page_hash_mismatch: bool,
    pub injected_library_count: u16,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct HookInjectionEvaluator;

impl HookInjectionEvaluator {
    #[must_use]
    pub fn evaluate(observation: &HookInjectionObservation) -> SignalSet {
        let mut signals = SignalSet::default();

        if observation.inline_hook_evidence {
            signals.push(RaspSignal::new(
                "hook.inline_hook_evidence",
                SignalCategory::HookInjection,
                SignalSeverity::Critical,
                EvidenceStrength::Definitive,
                SignalSource::NativeRuntime,
                "native code contains evidence consistent with an inline hook",
            ));
        }

        if observation.import_table_redirect {
            signals.push(RaspSignal::new(
                "hook.import_table_redirect",
                SignalCategory::HookInjection,
                SignalSeverity::Critical,
                EvidenceStrength::Definitive,
                SignalSource::NativeRuntime,
                "an imported function target differs from the protected expectation",
            ));
        }

        if observation.writable_executable_mapping {
            signals.push(RaspSignal::new(
                "hook.writable_executable_mapping",
                SignalCategory::HookInjection,
                SignalSeverity::High,
                EvidenceStrength::Strong,
                SignalSource::LinuxProcfs,
                "a writable and executable process mapping was reported",
            ));
        }

        if observation.code_page_hash_mismatch {
            signals.push(RaspSignal::new(
                "hook.code_page_hash_mismatch",
                SignalCategory::HookInjection,
                SignalSeverity::Critical,
                EvidenceStrength::Definitive,
                SignalSource::NativeRuntime,
                "a protected executable code page no longer matches its expected digest",
            ));
        }

        if observation.injected_library_count > 0 {
            signals.push(
                RaspSignal::new(
                    "hook.injected_library_count",
                    SignalCategory::HookInjection,
                    SignalSeverity::High,
                    EvidenceStrength::Strong,
                    SignalSource::NativeRuntime,
                    "unexpected runtime libraries were reported",
                )
                .with_detail("count", observation.injected_library_count.to_string()),
            );
        }

        signals
    }
}
