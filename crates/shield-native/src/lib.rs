//! Nexora Shield Phase F native runtime.
//!
//! The crate is intentionally modular: portable policy/integrity logic remains
//! safe Rust while the Android JNI surface is small, explicit and testable.
//! Android builds emit a `cdylib`; host builds also expose an `rlib` for
//! deterministic unit and regression testing.

#![deny(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::similar_names
)]

mod abi;
mod error;
mod generated;
mod hardening;
mod integrity;
mod jni_bridge;
mod runtime;
mod symbols;

pub use abi::{Abi, AbiDecision, AbiPolicy, PRIMARY_ANDROID_ABIS};
pub use error::{NativeError, Result};
pub use generated::{GeneratedNativeData, GENERATED_NATIVE_DATA_VERSION};
pub use hardening::{HardeningProfile, PRODUCTION_LINKER_ARGS};
pub use integrity::{NativeDigest, NativeIntegrityCheck, NativeRegion};
pub use runtime::{NativeRuntimeDescriptor, NATIVE_RUNTIME_API_VERSION};
pub use symbols::{ExportPolicy, REQUIRED_JNI_EXPORTS};
