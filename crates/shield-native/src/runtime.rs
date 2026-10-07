use serde::{Deserialize, Serialize};

pub const NATIVE_RUNTIME_API_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeRuntimeDescriptor {
    pub api_version: u32,
    pub crate_version: String,
    pub target_arch: String,
}

impl NativeRuntimeDescriptor {
    #[must_use]
    pub fn current() -> Self {
        Self {
            api_version: NATIVE_RUNTIME_API_VERSION,
            crate_version: env!("CARGO_PKG_VERSION").to_owned(),
            target_arch: std::env::consts::ARCH.to_owned(),
        }
    }
}
