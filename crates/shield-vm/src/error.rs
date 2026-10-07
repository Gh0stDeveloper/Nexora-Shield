use std::fmt;

pub type Result<T> = std::result::Result<T, VmError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmError {
    EmptyBuildId,
    EmptySeed,
    IneligibleMethod { method_idx: u32, reason: String },
    UnsupportedDexOpcode { offset: u32, opcode: u8 },
    InvalidRegister(u16),
    InvalidConstant(u16),
    InvalidJump { from: usize, target: usize },
    InvalidHandler { target: usize },
    InvalidValueType(&'static str),
    ArgumentCount { expected: usize, actual: usize },
    DivisionByZero,
    Host(String),
    UnhandledException { type_name: Option<String> },
    StepLimitExceeded { limit: u64 },
    MissingReturn,
    InvalidOpcode(u8),
    MetadataSealMismatch,
    MetadataEncoding(String),
    InvalidSelector(String),
}

impl fmt::Display for VmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBuildId => formatter.write_str("VM build id must not be empty"),
            Self::EmptySeed => formatter.write_str("VM private seed must not be empty"),
            Self::IneligibleMethod { method_idx, reason } => {
                write!(formatter, "method {method_idx} is not eligible for VM Shield: {reason}")
            }
            Self::UnsupportedDexOpcode { offset, opcode } => {
                write!(formatter, "unsupported DEX opcode 0x{opcode:02x} at code offset {offset}")
            }
            Self::InvalidRegister(register) => write!(formatter, "invalid VM register v{register}"),
            Self::InvalidConstant(index) => write!(formatter, "invalid VM constant #{index}"),
            Self::InvalidJump { from, target } => {
                write!(formatter, "invalid VM jump from pc {from} to pc {target}")
            }
            Self::InvalidHandler { target } => {
                write!(formatter, "invalid VM exception handler target pc {target}")
            }
            Self::InvalidValueType(expected) => {
                write!(formatter, "VM value does not match expected type {expected}")
            }
            Self::ArgumentCount { expected, actual } => {
                write!(formatter, "VM expected {expected} arguments but received {actual}")
            }
            Self::DivisionByZero => formatter.write_str("VM integer division by zero"),
            Self::Host(message) => write!(formatter, "VM host error: {message}"),
            Self::UnhandledException { type_name } => match type_name {
                Some(name) => write!(formatter, "unhandled VM exception {name}"),
                None => formatter.write_str("unhandled VM exception"),
            },
            Self::StepLimitExceeded { limit } => {
                write!(formatter, "VM execution exceeded step limit {limit}")
            }
            Self::MissingReturn => formatter.write_str("VM method terminated without return"),
            Self::InvalidOpcode(opcode) => write!(formatter, "unknown allocated VM opcode {opcode}"),
            Self::MetadataSealMismatch => formatter.write_str("VM metadata authentication failed"),
            Self::MetadataEncoding(message) => {
                write!(formatter, "VM metadata encoding error: {message}")
            }
            Self::InvalidSelector(message) => write!(formatter, "invalid VM selector: {message}"),
        }
    }
}

impl std::error::Error for VmError {}
