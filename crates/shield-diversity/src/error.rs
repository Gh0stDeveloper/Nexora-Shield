use std::fmt;

pub type Result<T> = std::result::Result<T, DiversityError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiversityError {
    EmptyPrivateSeed,
    WeakPrivateSeed { observed: usize, minimum: usize },
    EmptyApplicationId,
    EmptyBuildId,
    EmptyModeValue,
    InvalidPartitionBounds,
    MissingCertificateRoot,
    MissingPackageNode,
    Integrity(String),
    Cfg(String),
    Vm(String),
    Native(String),
    Encoding(String),
}

impl fmt::Display for DiversityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPrivateSeed => formatter.write_str("private diversity seed must not be empty"),
            Self::WeakPrivateSeed { observed, minimum } => write!(
                formatter,
                "private diversity seed has {observed} bytes; at least {minimum} are required"
            ),
            Self::EmptyApplicationId => formatter.write_str("application id must not be empty"),
            Self::EmptyBuildId => formatter.write_str("build id must not be empty"),
            Self::EmptyModeValue => formatter.write_str("diversity mode value must not be empty"),
            Self::InvalidPartitionBounds => {
                formatter.write_str("string partition bounds are invalid")
            }
            Self::MissingCertificateRoot => {
                formatter.write_str("integrity graph has no certificate root")
            }
            Self::MissingPackageNode => {
                formatter.write_str("integrity graph has no package node")
            }
            Self::Integrity(message) => write!(formatter, "integrity diversification failed: {message}"),
            Self::Cfg(message) => write!(formatter, "CFG diversification failed: {message}"),
            Self::Vm(message) => write!(formatter, "VM diversification failed: {message}"),
            Self::Native(message) => write!(formatter, "native diversification failed: {message}"),
            Self::Encoding(message) => write!(formatter, "diversity encoding failed: {message}"),
        }
    }
}

impl std::error::Error for DiversityError {}
