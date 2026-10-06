use std::fmt;
use std::io;
use std::path::PathBuf;

/// Errors produced while inspecting, normalizing or signing Android packages.
#[derive(Debug)]
pub enum PackageError {
    Io(io::Error),
    InvalidZip(String),
    UnsupportedZip(String),
    MissingManifest,
    DuplicateEntry(String),
    InvalidEntryName(String),
    ToolNotFound(String),
    ToolFailed {
        tool: PathBuf,
        status: Option<i32>,
        stderr: String,
    },
    MissingEnvironmentVariable(String),
    InvalidArgument(String),
    VerificationFailed(String),
}

impl fmt::Display for PackageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::InvalidZip(message) => write!(formatter, "invalid ZIP/APK: {message}"),
            Self::UnsupportedZip(message) => write!(formatter, "unsupported ZIP/APK: {message}"),
            Self::MissingManifest => formatter.write_str("APK does not contain AndroidManifest.xml"),
            Self::DuplicateEntry(name) => write!(formatter, "ZIP contains duplicate entry '{name}'"),
            Self::InvalidEntryName(name) => write!(formatter, "unsafe or invalid ZIP entry name '{name}'"),
            Self::ToolNotFound(tool) => write!(formatter, "Android build tool '{tool}' was not found"),
            Self::ToolFailed {
                tool,
                status,
                stderr,
            } => write!(
                formatter,
                "tool '{}' failed with status {:?}: {}",
                tool.display(),
                status,
                stderr.trim()
            ),
            Self::MissingEnvironmentVariable(name) => {
                write!(formatter, "required environment variable '{name}' is not set")
            }
            Self::InvalidArgument(message) => write!(formatter, "invalid argument: {message}"),
            Self::VerificationFailed(message) => write!(formatter, "verification failed: {message}"),
        }
    }
}

impl std::error::Error for PackageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for PackageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Package-layer result type.
pub type Result<T> = std::result::Result<T, PackageError>;
