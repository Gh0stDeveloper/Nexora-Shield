use std::fmt;

pub type Result<T> = std::result::Result<T, LabError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabError {
    InvalidRule(String),
    InvalidCorpus(String),
    InvalidPerformanceSample(String),
    InvalidMethodology(String),
    InvalidAuditInput(String),
    Io(String),
    Json(String),
}

impl fmt::Display for LabError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRule(message) => write!(formatter, "invalid exposure rule: {message}"),
            Self::InvalidCorpus(message) => {
                write!(formatter, "invalid regression corpus: {message}")
            }
            Self::InvalidPerformanceSample(message) => {
                write!(formatter, "invalid performance sample: {message}")
            }
            Self::InvalidMethodology(message) => {
                write!(formatter, "invalid benchmark methodology: {message}")
            }
            Self::InvalidAuditInput(message) => write!(formatter, "invalid audit input: {message}"),
            Self::Io(message) => write!(formatter, "I/O error: {message}"),
            Self::Json(message) => write!(formatter, "JSON error: {message}"),
        }
    }
}

impl std::error::Error for LabError {}

impl From<std::io::Error> for LabError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<serde_json::Error> for LabError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}
