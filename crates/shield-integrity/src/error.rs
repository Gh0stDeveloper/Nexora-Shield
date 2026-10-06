use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityError {
    InvalidDigest(String),
    InvalidCertificateBinding(String),
    InvalidPackageIdentity(String),
    InvalidRegion(String),
    InvalidArtifact(String),
    InvalidGraph(String),
    InvalidDistribution(String),
    InvalidManifest(String),
    MissingEvidence(String),
    Io(String),
    Serialization(String),
    Dex(String),
}

impl fmt::Display for IntegrityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDigest(message) => write!(formatter, "invalid digest: {message}"),
            Self::InvalidCertificateBinding(message) => {
                write!(formatter, "invalid certificate binding: {message}")
            }
            Self::InvalidPackageIdentity(message) => {
                write!(formatter, "invalid package identity: {message}")
            }
            Self::InvalidRegion(message) => write!(formatter, "invalid integrity region: {message}"),
            Self::InvalidArtifact(message) => write!(formatter, "invalid artifact: {message}"),
            Self::InvalidGraph(message) => write!(formatter, "invalid integrity graph: {message}"),
            Self::InvalidDistribution(message) => {
                write!(formatter, "invalid distributed-check plan: {message}")
            }
            Self::InvalidManifest(message) => write!(formatter, "invalid integrity manifest: {message}"),
            Self::MissingEvidence(message) => write!(formatter, "missing integrity evidence: {message}"),
            Self::Io(message) => write!(formatter, "I/O error: {message}"),
            Self::Serialization(message) => write!(formatter, "serialization error: {message}"),
            Self::Dex(message) => write!(formatter, "DEX integrity error: {message}"),
        }
    }
}

impl std::error::Error for IntegrityError {}

pub type Result<T> = std::result::Result<T, IntegrityError>;

impl From<std::io::Error> for IntegrityError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<serde_json::Error> for IntegrityError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error.to_string())
    }
}

impl From<nexora_shield_dex::DexError> for IntegrityError {
    fn from(error: nexora_shield_dex::DexError) -> Self {
        Self::Dex(error.to_string())
    }
}
