use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DexError {
    Truncated { context: String, offset: usize },
    InvalidHeader(String),
    InvalidIntegrity(String),
    InvalidIndex { kind: &'static str, index: u32 },
    InvalidOffset { context: String, offset: u32 },
    InvalidLeb128 { offset: usize },
    InvalidMutf8 { offset: usize, reason: String },
    UnsupportedOpcode { opcode: u8, offset: u32 },
    InvalidInstruction { offset: u32, reason: String },
    InvalidControlFlow { offset: u32, target: i64 },
    InvalidSelector(String),
    UnsafeRename(String),
    InvalidMultiDex(String),
}

impl fmt::Display for DexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { context, offset } => {
                write!(formatter, "truncated DEX while reading {context} at 0x{offset:x}")
            }
            Self::InvalidHeader(message) => write!(formatter, "invalid DEX header: {message}"),
            Self::InvalidIntegrity(message) => write!(formatter, "invalid DEX integrity: {message}"),
            Self::InvalidIndex { kind, index } => write!(formatter, "invalid {kind} index {index}"),
            Self::InvalidOffset { context, offset } => {
                write!(formatter, "invalid offset for {context}: 0x{offset:x}")
            }
            Self::InvalidLeb128 { offset } => write!(formatter, "invalid LEB128 at 0x{offset:x}"),
            Self::InvalidMutf8 { offset, reason } => {
                write!(formatter, "invalid modified UTF-8 at 0x{offset:x}: {reason}")
            }
            Self::UnsupportedOpcode { opcode, offset } => {
                write!(formatter, "unsupported DEX opcode 0x{opcode:02x} at code unit {offset}")
            }
            Self::InvalidInstruction { offset, reason } => {
                write!(formatter, "invalid instruction at code unit {offset}: {reason}")
            }
            Self::InvalidControlFlow { offset, target } => {
                write!(formatter, "invalid branch from code unit {offset} to {target}")
            }
            Self::InvalidSelector(message) => write!(formatter, "invalid selector: {message}"),
            Self::UnsafeRename(message) => write!(formatter, "unsafe rename: {message}"),
            Self::InvalidMultiDex(message) => write!(formatter, "invalid multidex set: {message}"),
        }
    }
}

impl std::error::Error for DexError {}

pub type Result<T> = std::result::Result<T, DexError>;
