//! Nexora Shield Phase E runtime application self-protection engine.
//!
//! This crate models normalized runtime security evidence. Platform adapters
//! collect observations; this portable layer turns them into deterministic,
//! auditable signals without terminating the application or performing
//! destructive actions.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::struct_excessive_bools
)]

mod debug;
mod hook;
mod instrumentation;
mod signal;

pub use debug::{DebugEvaluator, DebugObservation};
pub use hook::{HookInjectionEvaluator, HookInjectionObservation};
pub use instrumentation::{InstrumentationEvaluator, InstrumentationObservation};
pub use signal::{
    EvidenceStrength, RaspSignal, SignalCategory, SignalSet, SignalSeverity, SignalSource,
};
