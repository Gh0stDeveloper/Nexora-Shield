use std::fmt;

pub type Result<T> = std::result::Result<T, NativeError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeError {
    EmptyBuildId,
    EmptySeed,
    EmptyRegionLabel,
    UnsupportedAbi(String),
}

impl fmt::Display for NativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBuildId => formatter.write_str("native build id must not be empty"),
            Self::EmptySeed => formatter.write_str("native generation seed must not be empty"),
            Self::EmptyRegionLabel => formatter.write_str("native region label must not be empty"),
            Self::UnsupportedAbi(abi) => write!(formatter, "unsupported Android ABI '{abi}'"),
        }
    }
}

impl std::error::Error for NativeError {}
