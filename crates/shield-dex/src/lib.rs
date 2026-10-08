//! Nexora Shield Phase B DEX engine.
//!
//! The engine parses standard DEX, validates structural/runtime invariants,
//! builds CFG/type/SSA representations, resolves selectors, analyzes
//! reflection/JNI compatibility, performs fixed-layout safe renaming and
//! metadata reduction, and rewrites canonical multidex sets.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

mod analysis;
mod cfg;
mod checksum;
mod compatibility;
mod error;
mod graph;
mod ir;
mod model;
mod multidex;
mod parser;
mod selector;
mod transform;
mod validator;

pub use analysis::{BlockTypeState, RegisterType, TypeAnalysis, TypeAnalyzer};
pub use cfg::{BasicBlock, ControlFlowGraph};
pub use checksum::{adler32, refresh_integrity, sha1, verify_integrity};
pub use compatibility::{CompatibilityAnalyzer, CompatibilityReport};
pub use error::{DexError, Result};
pub use graph::{EdgeKind, GraphNode, ReferenceEdge, ReferenceGraph};
pub use ir::{IrBlock, IrInstruction, IrMethod, IrPhi, SsaValue};
pub use model::{
    CatchHandler, ClassData, ClassDef, CodeItem, DexFile, DexHeader, DexString, EncodedField,
    EncodedMethod, FieldId, Instruction, MethodId, ProtoId, PseudoInstruction, ReferenceKind,
    TryItem, TypeId, ACC_NATIVE, ACC_STATIC, DEX_ENDIAN_CONSTANT, DEX_HEADER_SIZE, NO_INDEX,
};
pub use multidex::{
    canonical_dex_index, canonical_dex_name, DexInput, DexRewriteOutput, DexUnit,
    MultiDexRewriteConfig, MultiDexSet,
};
pub use parser::DexParser;
pub use selector::{glob_match, Selection, Selector, SelectorKind, SelectorResolver};
pub use transform::{
    DexRewriteAudit, DexRewriteVerifier, DexWriter, MetadataReducer, MetadataReductionReport,
    RenameConfig, RenamePass, RenameRecord,
    RenameReport, RenameResult,
};
pub use validator::{DexValidator, ValidationReport};
