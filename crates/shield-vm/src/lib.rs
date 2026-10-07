//! Nexora Shield Phase G VM Shield.
//!
//! The VM is selective by design. Methods are virtualized only after an
//! eligibility gate proves that the current lowering/runtime contract can
//! preserve their supported semantics.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::too_many_lines
)]

mod constant_pool;
mod eligibility;
mod error;
mod host;
mod interpreter;
mod ir;
mod lowering;
mod opcode;
mod perf;
mod seal;
mod security;
mod selection;
mod value;

pub use constant_pool::{ConstantPool, VmConstant};
pub use eligibility::{
    EligibilityAnalyzer, EligibilityFeature, EligibilityPolicy, EligibilityReason,
    EligibilityReport,
};
pub use error::{Result, VmError};
pub use host::{NullHost, VmHost};
pub use interpreter::{ExecutionConfig, ExecutionResult, Interpreter, SealedExecution};
pub use ir::{
    BranchCondition, VmException, VmExceptionHandler, VmInstruction, VmMethod, VmRegister,
};
pub use lowering::DexLowerer;
pub use opcode::{OpcodeAllocation, OpcodeStream, SemanticOpcode, ALL_SEMANTIC_OPCODES};
pub use perf::{PerformanceEstimate, PerformanceEstimator};
pub use seal::{MetadataSealer, SealedMetadata, VmMetadata};
pub use security::{SecurityBenchmarkReport, VmSecurityBenchmark};
pub use selection::{
    SelectionPlan, SelectionPlanner, VmSelectionConfig, VmSelectionMode, VmSelector,
};
pub use value::VmValue;
