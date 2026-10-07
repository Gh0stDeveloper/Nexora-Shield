use nexora_shield_dex::{DexFile, IrMethod};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EligibilityPolicy {
    pub max_registers: u16,
    pub max_instructions: usize,
    pub allow_calls: bool,
    pub allow_fields: bool,
    pub allow_exceptions: bool,
}

impl Default for EligibilityPolicy {
    fn default() -> Self {
        Self {
            max_registers: 128,
            max_instructions: 4_096,
            allow_calls: true,
            allow_fields: true,
            allow_exceptions: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum EligibilityReason {
    MissingCode,
    TooManyRegisters { observed: u16, maximum: u16 },
    TooManyInstructions { observed: usize, maximum: usize },
    UnsupportedOpcode { offset: u32, opcode: u8 },
    CallsDisabled,
    FieldsDisabled,
    ExceptionsDisabled,
    WideMoveResultUnsupported { offset: u32 },
    MalformedIr(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EligibilityFeature {
    Calls,
    Fields,
    Exceptions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EligibilityReport {
    pub method_idx: u32,
    pub eligible: bool,
    pub register_count: u16,
    pub instruction_count: usize,
    pub features: std::collections::BTreeSet<EligibilityFeature>,
    pub reasons: Vec<EligibilityReason>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct EligibilityAnalyzer;

impl EligibilityAnalyzer {
    #[must_use]
    pub fn analyze(dex: &DexFile, method_idx: u32, policy: EligibilityPolicy) -> EligibilityReport {
        let Some(code) = dex.code_for_method(method_idx) else {
            return EligibilityReport {
                method_idx,
                eligible: false,
                register_count: 0,
                instruction_count: 0,
                features: std::collections::BTreeSet::new(),
                reasons: vec![EligibilityReason::MissingCode],
            };
        };

        let executable = code
            .instructions
            .iter()
            .filter(|instruction| !instruction.is_payload())
            .collect::<Vec<_>>();
        let mut reasons = Vec::new();
        let has_calls = executable
            .iter()
            .any(|instruction| is_call(instruction.opcode));
        let has_fields = executable
            .iter()
            .any(|instruction| is_field(instruction.opcode));
        let has_exceptions = !code.tries.is_empty();

        if code.registers_size > policy.max_registers {
            reasons.push(EligibilityReason::TooManyRegisters {
                observed: code.registers_size,
                maximum: policy.max_registers,
            });
        }
        if executable.len() > policy.max_instructions {
            reasons.push(EligibilityReason::TooManyInstructions {
                observed: executable.len(),
                maximum: policy.max_instructions,
            });
        }
        if has_calls && !policy.allow_calls {
            reasons.push(EligibilityReason::CallsDisabled);
        }
        if has_fields && !policy.allow_fields {
            reasons.push(EligibilityReason::FieldsDisabled);
        }
        if has_exceptions && !policy.allow_exceptions {
            reasons.push(EligibilityReason::ExceptionsDisabled);
        }

        for instruction in &executable {
            if instruction.opcode == 0x0b {
                reasons.push(EligibilityReason::WideMoveResultUnsupported {
                    offset: instruction.offset,
                });
            } else if !is_supported_opcode(instruction.opcode) {
                reasons.push(EligibilityReason::UnsupportedOpcode {
                    offset: instruction.offset,
                    opcode: instruction.opcode,
                });
            }
        }

        if let Err(error) = IrMethod::build(dex, method_idx) {
            reasons.push(EligibilityReason::MalformedIr(error.to_string()));
        }

        let mut features = std::collections::BTreeSet::new();
        if has_calls {
            features.insert(EligibilityFeature::Calls);
        }
        if has_fields {
            features.insert(EligibilityFeature::Fields);
        }
        if has_exceptions {
            features.insert(EligibilityFeature::Exceptions);
        }

        EligibilityReport {
            method_idx,
            eligible: reasons.is_empty(),
            register_count: code.registers_size,
            instruction_count: executable.len(),
            features,
            reasons,
        }
    }
}

const fn is_call(opcode: u8) -> bool {
    matches!(opcode, 0x6e..=0x72 | 0x74..=0x78)
}

const fn is_field(opcode: u8) -> bool {
    matches!(opcode, 0x52..=0x6d)
}

#[must_use]
pub const fn is_supported_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        0x00
            | 0x01..=0x03
            | 0x07..=0x0a
            | 0x0c..=0x0f
            | 0x11..=0x15
            | 0x1a..=0x1c
            | 0x27..=0x2a
            | 0x32..=0x3d
            | 0x52..=0x72
            | 0x74..=0x78
            | 0x7b
            | 0x90..=0x97
            | 0xb0..=0xb7
    )
}
