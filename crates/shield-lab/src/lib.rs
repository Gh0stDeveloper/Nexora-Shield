//! Nexora Shield Phase M defensive Security Lab.
//!
//! The lab turns known security assumptions and bypass classes into reproducible
//! regression gates. It is intended for authorized testing of Nexora Shield,
//! its samples and applications owned by the operator.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::too_many_lines
)]

mod audit;
mod benchmark;
mod corpus;
mod environment;
mod error;
mod fuzz;
mod performance;
mod portability;
mod runtime;
mod score;
mod static_exposure;
mod tamper;

pub use audit::{
    AuditEvidenceClass, AuditEvidenceItem, AuditPreparation, AuditReadinessInput,
    AuditReadinessReport, AuditRequirement,
};
pub use benchmark::{BenchmarkControl, ComparativeBenchmarkMethodology};
pub use corpus::{RegressionCase, RegressionCategory, RegressionCorpus};
pub use environment::{
    ModifiedEnvironmentCase, ModifiedEnvironmentLab, ModifiedEnvironmentReport,
    ModifiedEnvironmentResult,
};
pub use error::{LabError, Result};
pub use fuzz::{FuzzFarm, FuzzReport};
pub use performance::{PerformanceBudget, PerformanceFarm, PerformanceReport, PerformanceSample};
pub use portability::{PortabilityGateReport, PortabilityLab};
pub use runtime::{
    RuntimeInstrumentationCase, RuntimeInstrumentationLab, RuntimeInstrumentationReport,
    RuntimeInstrumentationResult,
};
pub use score::{SecurityControlResult, SecurityScore, SecurityScoreReport};
pub use static_exposure::{
    ExposureFinding, ExposureRule, StaticExposureHarness, StaticExposureReport,
};
pub use tamper::{TamperCaseResult, TamperKind, TamperLab, TamperLabReport, TamperObservation};
