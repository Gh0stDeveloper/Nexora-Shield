use nexora_shield_package::PackageError;
use std::fmt;
use std::io;

/// Errors raised by the orchestration layer.
#[derive(Debug)]
pub enum CoreError {
    Package(PackageError),
    Io(io::Error),
    InvalidRequest(String),
    Transaction(String),
    Clock(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Package(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::InvalidRequest(message) => write!(formatter, "invalid request: {message}"),
            Self::Transaction(message) => write!(formatter, "transaction failed: {message}"),
            Self::Clock(message) => write!(formatter, "clock error: {message}"),
        }
    }
}

impl std::error::Error for CoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Package(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PackageError> for CoreError {
    fn from(error: PackageError) -> Self {
        Self::Package(error)
    }
}

impl From<io::Error> for CoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Core result type.
pub type Result<T> = std::result::Result<T, CoreError>;
