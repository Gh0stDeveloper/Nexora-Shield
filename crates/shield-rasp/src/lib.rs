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
mod emulator;
mod hook;
mod instrumentation;
mod integrity_fusion;
mod modified_system;
mod policy;
mod response;
mod risk;
mod signal;

pub use debug::{DebugEvaluator, DebugObservation};
pub use emulator::{EmulatorEvaluator, EmulatorObservation};
pub use hook::{HookInjectionEvaluator, HookInjectionObservation};
pub use instrumentation::{InstrumentationEvaluator, InstrumentationObservation};
pub use integrity_fusion::IntegritySignalFusion;
pub use modified_system::{ModifiedSystemEvaluator, ModifiedSystemObservation};
pub use policy::{CompiledPolicy, PolicyError, PolicySpec};
pub use response::{RaspResponse, ResponseDecision, ResponseEngine};
pub use risk::{RiskAssessment, RiskEngine, RiskLevel, RiskReason, RiskThresholds};
pub use signal::{
    EvidenceStrength, RaspSignal, SignalCategory, SignalSet, SignalSeverity, SignalSource,
};
