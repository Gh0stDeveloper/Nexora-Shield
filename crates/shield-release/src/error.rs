use std::fmt;

pub type Result<T> = std::result::Result<T, ReleaseError>;

#[derive(Debug)]
pub enum ReleaseError {
    InvalidApiContract(String),
    InvalidMigration(String),
    InvalidVersion(String),
    InvalidQualification(String),
    InvalidCompatibility(String),
    Io(String),
    Json(String),
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidApiContract(message) => {
                write!(formatter, "invalid API contract: {message}")
            }
            Self::InvalidMigration(message) => {
                write!(formatter, "invalid config migration: {message}")
            }
            Self::InvalidVersion(message) => {
                write!(formatter, "invalid release version: {message}")
            }
            Self::InvalidQualification(message) => {
                write!(formatter, "invalid release qualification: {message}")
            }
            Self::InvalidCompatibility(message) => {
                write!(formatter, "invalid compatibility matrix: {message}")
            }
            Self::Io(message) => write!(formatter, "I/O error: {message}"),
            Self::Json(message) => write!(formatter, "JSON error: {message}"),
        }
    }
}

impl std::error::Error for ReleaseError {}

impl From<std::io::Error> for ReleaseError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<serde_json::Error> for ReleaseError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}
