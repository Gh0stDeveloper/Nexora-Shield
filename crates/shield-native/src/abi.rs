use crate::error::{NativeError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Abi {
    Arm64V8a,
    X86_64,
    ArmeabiV7a,
    X86,
}

pub const PRIMARY_ANDROID_ABIS: [Abi; 2] = [Abi::Arm64V8a, Abi::X86_64];

impl Abi {
    #[must_use]
    pub const fn android_name(self) -> &'static str {
        match self {
            Self::Arm64V8a => "arm64-v8a",
            Self::X86_64 => "x86_64",
            Self::ArmeabiV7a => "armeabi-v7a",
            Self::X86 => "x86",
        }
    }

    #[must_use]
    pub const fn rust_target(self) -> &'static str {
        match self {
            Self::Arm64V8a => "aarch64-linux-android",
            Self::X86_64 => "x86_64-linux-android",
            Self::ArmeabiV7a => "armv7-linux-androideabi",
            Self::X86 => "i686-linux-android",
        }
    }

    #[must_use]
    pub const fn is_primary(self) -> bool {
        matches!(self, Self::Arm64V8a | Self::X86_64)
    }

    #[must_use]
    pub const fn is_64_bit(self) -> bool {
        matches!(self, Self::Arm64V8a | Self::X86_64)
    }
}

impl FromStr for Abi {
    type Err = NativeError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "arm64-v8a" => Ok(Self::Arm64V8a),
            "x86_64" => Ok(Self::X86_64),
            "armeabi-v7a" => Ok(Self::ArmeabiV7a),
            "x86" => Ok(Self::X86),
            _ => Err(NativeError::UnsupportedAbi(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbiDecision {
    Primary,
    AdditionalAllowed,
    Rejected,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiPolicy {
    allow_32_bit: bool,
    additional: BTreeSet<Abi>,
}


impl AbiPolicy {
    #[must_use]
    pub fn with_additional(allow_32_bit: bool, additional: impl IntoIterator<Item = Abi>) -> Self {
        Self {
            allow_32_bit,
            additional: additional.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn decision(&self, abi: Abi) -> AbiDecision {
        if abi.is_primary() {
            AbiDecision::Primary
        } else if self.allow_32_bit && self.additional.contains(&abi) {
            AbiDecision::AdditionalAllowed
        } else {
            AbiDecision::Rejected
        }
    }

    #[must_use]
    pub fn allows(&self, abi: Abi) -> bool {
        self.decision(abi) != AbiDecision::Rejected
    }

    #[must_use]
    pub const fn allow_32_bit(&self) -> bool {
        self.allow_32_bit
    }
}
