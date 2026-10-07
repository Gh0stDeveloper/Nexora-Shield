use crate::constant_pool::ConstantPool;
use crate::error::{Result, VmError};
use crate::value::VmValue;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VmRegister(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchCondition {
    Eq,
    Ne,
    Lt,
    Ge,
    Gt,
    Le,
    EqZero,
    NeZero,
    LtZero,
    GeZero,
    GtZero,
    LeZero,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmException {
    pub type_name: Option<String>,
    pub value: VmValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmExceptionHandler {
    pub start: usize,
    pub end: usize,
    pub target: usize,
    pub type_name: Option<String>,
    pub exception_register: Option<VmRegister>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum VmInstruction {
    Nop,
    LoadConst {
        dst: VmRegister,
        constant: u16,
    },
    Move {
        dst: VmRegister,
        src: VmRegister,
    },
    Add {
        dst: VmRegister,
        left: VmRegister,
        right: VmRegister,
    },
    Sub {
        dst: VmRegister,
        left: VmRegister,
        right: VmRegister,
    },
    Mul {
        dst: VmRegister,
        left: VmRegister,
        right: VmRegister,
    },
    Div {
        dst: VmRegister,
        left: VmRegister,
        right: VmRegister,
    },
    Rem {
        dst: VmRegister,
        left: VmRegister,
        right: VmRegister,
    },
    And {
        dst: VmRegister,
        left: VmRegister,
        right: VmRegister,
    },
    Or {
        dst: VmRegister,
        left: VmRegister,
        right: VmRegister,
    },
    Xor {
        dst: VmRegister,
        left: VmRegister,
        right: VmRegister,
    },
    Neg {
        dst: VmRegister,
        src: VmRegister,
    },
    Jump {
        target: usize,
    },
    Branch {
        condition: BranchCondition,
        left: VmRegister,
        right: Option<VmRegister>,
        target: usize,
    },
    LoadField {
        dst: VmRegister,
        object: Option<VmRegister>,
        field: u32,
    },
    StoreField {
        object: Option<VmRegister>,
        field: u32,
        src: VmRegister,
    },
    Call {
        dst: Option<VmRegister>,
        method: u32,
        args: Vec<VmRegister>,
    },
    Throw {
        src: VmRegister,
    },
    Return {
        src: VmRegister,
    },
    ReturnVoid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmMethod {
    pub method_idx: u32,
    pub register_count: u16,
    pub parameter_registers: Vec<VmRegister>,
    pub instructions: Vec<VmInstruction>,
    pub constants: ConstantPool,
    pub handlers: Vec<VmExceptionHandler>,
}

impl VmMethod {
    pub fn validate(&self) -> Result<()> {
        for register in &self.parameter_registers {
            self.validate_register(*register)?;
        }

        for (pc, instruction) in self.instructions.iter().enumerate() {
            for register in instruction.registers() {
                self.validate_register(register)?;
            }

            match instruction {
                VmInstruction::LoadConst { constant, .. } => {
                    self.constants.get(*constant)?;
                }
                VmInstruction::Jump { target } | VmInstruction::Branch { target, .. }
                    if *target >= self.instructions.len() =>
                {
                    return Err(VmError::InvalidJump {
                        from: pc,
                        target: *target,
                    });
                }
                _ => {}
            }
        }

        for handler in &self.handlers {
            if handler.start > handler.end
                || handler.end > self.instructions.len()
                || handler.target >= self.instructions.len()
            {
                return Err(VmError::InvalidHandler {
                    target: handler.target,
                });
            }
            if let Some(register) = handler.exception_register {
                self.validate_register(register)?;
            }
        }

        Ok(())
    }

    fn validate_register(&self, register: VmRegister) -> Result<()> {
        if register.0 < self.register_count {
            Ok(())
        } else {
            Err(VmError::InvalidRegister(register.0))
        }
    }
}

impl VmInstruction {
    #[must_use]
    pub fn registers(&self) -> Vec<VmRegister> {
        match self {
            Self::Nop | Self::Jump { .. } | Self::ReturnVoid => Vec::new(),
            Self::LoadConst { dst, .. } => vec![*dst],
            Self::Move { dst, src } | Self::Neg { dst, src } => vec![*dst, *src],
            Self::Add { dst, left, right }
            | Self::Sub { dst, left, right }
            | Self::Mul { dst, left, right }
            | Self::Div { dst, left, right }
            | Self::Rem { dst, left, right }
            | Self::And { dst, left, right }
            | Self::Or { dst, left, right }
            | Self::Xor { dst, left, right } => vec![*dst, *left, *right],
            Self::Branch { left, right, .. } => {
                let mut registers = vec![*left];
                if let Some(right) = right {
                    registers.push(*right);
                }
                registers
            }
            Self::LoadField { dst, object, .. } => {
                let mut registers = vec![*dst];
                if let Some(object) = object {
                    registers.push(*object);
                }
                registers
            }
            Self::StoreField { object, src, .. } => {
                let mut registers = vec![*src];
                if let Some(object) = object {
                    registers.push(*object);
                }
                registers
            }
            Self::Call { dst, args, .. } => {
                let mut registers = args.clone();
                if let Some(dst) = dst {
                    registers.push(*dst);
                }
                registers
            }
            Self::Throw { src } | Self::Return { src } => vec![*src],
        }
    }
}
