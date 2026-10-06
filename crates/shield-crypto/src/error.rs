use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataProtectionError {
    InvalidRootSecretLength {
        actual: usize,
    },
    InvalidIdentity(String),
    KeyDerivation(String),
    InvalidContainer(String),
    UnsupportedVersion(u8),
    KindMismatch {
        expected: u8,
        actual: u8,
    },
    IdentifierMismatch,
    AuthenticationFailed,
    InvalidUtf8,
    InvalidConstant(String),
    DuplicateIdentifier(String),
    ResourceRejected(String),
    InvalidResourcePath(String),
    InvalidBundle(String),
    Metadata(String),
    InvalidProbe(String),
    SizeLimitExceeded {
        context: String,
        size: u64,
        limit: u64,
    },
}

impl fmt::Display for DataProtectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRootSecretLength { actual } => {
                write!(
                    formatter,
                    "root secret must be exactly 32 bytes, got {actual}"
                )
            }
            Self::InvalidIdentity(message) => {
                write!(formatter, "invalid build identity: {message}")
            }
            Self::KeyDerivation(message) => write!(formatter, "key derivation failed: {message}"),
            Self::InvalidContainer(message) => {
                write!(formatter, "invalid protected container: {message}")
            }
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported protected-container version {version}"
                )
            }
            Self::KindMismatch { expected, actual } => {
                write!(
                    formatter,
                    "container kind mismatch: expected {expected}, got {actual}"
                )
            }
            Self::IdentifierMismatch => {
                formatter.write_str("protected-container identifier mismatch")
            }
            Self::AuthenticationFailed => {
                formatter.write_str("protected-container authentication failed")
            }
            Self::InvalidUtf8 => formatter.write_str("decrypted text is not valid UTF-8"),
            Self::InvalidConstant(message) => {
                write!(formatter, "invalid protected constant: {message}")
            }
            Self::DuplicateIdentifier(identifier) => {
                write!(formatter, "duplicate protected identifier '{identifier}'")
            }
            Self::ResourceRejected(message) => write!(formatter, "resource rejected: {message}"),
            Self::InvalidResourcePath(path) => write!(formatter, "invalid resource path '{path}'"),
            Self::InvalidBundle(message) => write!(formatter, "invalid resource bundle: {message}"),
            Self::Metadata(message) => write!(formatter, "private metadata error: {message}"),
            Self::InvalidProbe(message) => write!(formatter, "invalid exposure probe: {message}"),
            Self::SizeLimitExceeded {
                context,
                size,
                limit,
            } => write!(
                formatter,
                "{context} size {size} exceeds configured limit {limit}"
            ),
        }
    }
}

impl std::error::Error for DataProtectionError {}

pub type Result<T> = std::result::Result<T, DataProtectionError>;
