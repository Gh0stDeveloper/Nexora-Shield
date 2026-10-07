use crate::constant_pool::VmConstant;
use crate::error::{Result, VmError};
use crate::host::VmHost;
use crate::ir::{BranchCondition, VmException, VmInstruction, VmMethod, VmRegister};
use crate::value::VmValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionConfig {
    pub step_limit: u64,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            step_limit: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub value: VmValue,
    pub steps: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Interpreter;

impl Interpreter {
    pub fn execute<H: VmHost>(
        method: &VmMethod,
        args: &[VmValue],
        host: &mut H,
        config: ExecutionConfig,
    ) -> Result<ExecutionResult> {
        method.validate()?;
        if args.len() != method.parameter_registers.len() {
            return Err(VmError::ArgumentCount {
                expected: method.parameter_registers.len(),
                actual: args.len(),
            });
        }

        let mut registers = vec![VmValue::Uninitialized; usize::from(method.register_count)];
        for (register, value) in method.parameter_registers.iter().zip(args.iter()) {
            registers[usize::from(register.0)] = value.clone();
        }

        let mut pc = 0_usize;
        let mut steps = 0_u64;

        while pc < method.instructions.len() {
            if steps >= config.step_limit {
                return Err(VmError::StepLimitExceeded {
                    limit: config.step_limit,
                });
            }
            steps = steps.saturating_add(1);

            match &method.instructions[pc] {
                VmInstruction::Nop => pc += 1,
                VmInstruction::LoadConst { dst, constant } => {
                    registers[usize::from(dst.0)] =
                        constant_value(method.constants.get(*constant)?, *constant);
                    pc += 1;
                }
                VmInstruction::Move { dst, src } => {
                    registers[usize::from(dst.0)] = registers[usize::from(src.0)].clone();
                    pc += 1;
                }
                VmInstruction::Add { dst, left, right } => {
                    binary_int(&mut registers, *dst, *left, *right, i32::wrapping_add)?;
                    pc += 1;
                }
                VmInstruction::Sub { dst, left, right } => {
                    binary_int(&mut registers, *dst, *left, *right, i32::wrapping_sub)?;
                    pc += 1;
                }
                VmInstruction::Mul { dst, left, right } => {
                    binary_int(&mut registers, *dst, *left, *right, i32::wrapping_mul)?;
                    pc += 1;
                }
                VmInstruction::Div { dst, left, right } => {
                    let left_value = registers[usize::from(left.0)].as_int()?;
                    let right_value = registers[usize::from(right.0)].as_int()?;
                    if right_value == 0 {
                        pc = dispatch_exception(
                            method,
                            &mut registers,
                            pc,
                            VmException {
                                type_name: Some("Ljava/lang/ArithmeticException;".to_owned()),
                                value: VmValue::Null,
                            },
                        )?;
                    } else {
                        let value = if left_value == i32::MIN && right_value == -1 {
                            i32::MIN
                        } else {
                            left_value / right_value
                        };
                        registers[usize::from(dst.0)] = VmValue::Int(value);
                        pc += 1;
                    }
                }
                VmInstruction::Rem { dst, left, right } => {
                    let left_value = registers[usize::from(left.0)].as_int()?;
                    let right_value = registers[usize::from(right.0)].as_int()?;
                    if right_value == 0 {
                        pc = dispatch_exception(
                            method,
                            &mut registers,
                            pc,
                            VmException {
                                type_name: Some("Ljava/lang/ArithmeticException;".to_owned()),
                                value: VmValue::Null,
                            },
                        )?;
                    } else {
                        let value = if left_value == i32::MIN && right_value == -1 {
                            0
                        } else {
                            left_value % right_value
                        };
                        registers[usize::from(dst.0)] = VmValue::Int(value);
                        pc += 1;
                    }
                }
                VmInstruction::And { dst, left, right } => {
                    binary_int(&mut registers, *dst, *left, *right, |a, b| a & b)?;
                    pc += 1;
                }
                VmInstruction::Or { dst, left, right } => {
                    binary_int(&mut registers, *dst, *left, *right, |a, b| a | b)?;
                    pc += 1;
                }
                VmInstruction::Xor { dst, left, right } => {
                    binary_int(&mut registers, *dst, *left, *right, |a, b| a ^ b)?;
                    pc += 1;
                }
                VmInstruction::Neg { dst, src } => {
                    let value = registers[usize::from(src.0)].as_int()?;
                    registers[usize::from(dst.0)] = VmValue::Int(value.wrapping_neg());
                    pc += 1;
                }
                VmInstruction::Jump { target } => pc = *target,
                VmInstruction::Branch {
                    condition,
                    left,
                    right,
                    target,
                } => {
                    if branch_matches(
                        *condition,
                        &registers[usize::from(left.0)],
                        right.map(|register| &registers[usize::from(register.0)]),
                    )? {
                        pc = *target;
                    } else {
                        pc += 1;
                    }
                }
                VmInstruction::LoadField { dst, object, field } => {
                    let object_value = object.map(|register| &registers[usize::from(register.0)]);
                    match host.load_field(object_value, *field) {
                        Ok(value) => {
                            registers[usize::from(dst.0)] = value;
                            pc += 1;
                        }
                        Err(exception) => {
                            pc = dispatch_exception(method, &mut registers, pc, exception)?;
                        }
                    }
                }
                VmInstruction::StoreField { object, field, src } => {
                    let object_value =
                        object.map(|register| &registers[usize::from(register.0)]);
                    let value = &registers[usize::from(src.0)];
                    match host.store_field(object_value, *field, value) {
                        Ok(()) => pc += 1,
                        Err(exception) => {
                            pc = dispatch_exception(method, &mut registers, pc, exception)?;
                        }
                    }
                }
                VmInstruction::Call {
                    dst,
                    method: call,
                    args,
                } => {
                    let values = args
                        .iter()
                        .map(|register| registers[usize::from(register.0)].clone())
                        .collect::<Vec<_>>();
                    match host.call(*call, &values) {
                        Ok(value) => {
                            if let Some(dst) = dst {
                                registers[usize::from(dst.0)] = value;
                            }
                            pc += 1;
                        }
                        Err(exception) => {
                            pc = dispatch_exception(method, &mut registers, pc, exception)?;
                        }
                    }
                }
                VmInstruction::Throw { src } => {
                    let value = registers[usize::from(src.0)].clone();
                    let exception = VmException {
                        type_name: host.exception_type(&value),
                        value,
                    };
                    pc = dispatch_exception(method, &mut registers, pc, exception)?;
                }
                VmInstruction::Return { src } => {
                    return Ok(ExecutionResult {
                        value: registers[usize::from(src.0)].clone(),
                        steps,
                    });
                }
                VmInstruction::ReturnVoid => {
                    return Ok(ExecutionResult {
                        value: VmValue::Void,
                        steps,
                    });
                }
            }
        }

        Err(VmError::MissingReturn)
    }
}

fn constant_value(constant: &VmConstant, index: u16) -> VmValue {
    match constant {
        VmConstant::Int(value) => VmValue::Int(*value),
        VmConstant::String(_) | VmConstant::Type(_) => VmValue::Const(index),
    }
}

fn binary_int(
    registers: &mut [VmValue],
    dst: VmRegister,
    left: VmRegister,
    right: VmRegister,
    operation: fn(i32, i32) -> i32,
) -> Result<()> {
    let left = registers[usize::from(left.0)].as_int()?;
    let right = registers[usize::from(right.0)].as_int()?;
    registers[usize::from(dst.0)] = VmValue::Int(operation(left, right));
    Ok(())
}

fn branch_matches(
    condition: BranchCondition,
    left: &VmValue,
    right: Option<&VmValue>,
) -> Result<bool> {
    match condition {
        BranchCondition::Eq => Ok(left == required_right(right)?),
        BranchCondition::Ne => Ok(left != required_right(right)?),
        BranchCondition::Lt => Ok(left.as_int()? < required_right(right)?.as_int()?),
        BranchCondition::Ge => Ok(left.as_int()? >= required_right(right)?.as_int()?),
        BranchCondition::Gt => Ok(left.as_int()? > required_right(right)?.as_int()?),
        BranchCondition::Le => Ok(left.as_int()? <= required_right(right)?.as_int()?),
        BranchCondition::EqZero => Ok(left.as_int()? == 0),
        BranchCondition::NeZero => Ok(left.as_int()? != 0),
        BranchCondition::LtZero => Ok(left.as_int()? < 0),
        BranchCondition::GeZero => Ok(left.as_int()? >= 0),
        BranchCondition::GtZero => Ok(left.as_int()? > 0),
        BranchCondition::LeZero => Ok(left.as_int()? <= 0),
    }
}

fn required_right(right: Option<&VmValue>) -> Result<&VmValue> {
    right.ok_or(VmError::InvalidValueType("branch right operand"))
}

fn dispatch_exception(
    method: &VmMethod,
    registers: &mut [VmValue],
    pc: usize,
    exception: VmException,
) -> Result<usize> {
    for handler in &method.handlers {
        if pc < handler.start || pc >= handler.end {
            continue;
        }
        if !handler_matches(handler.type_name.as_deref(), exception.type_name.as_deref()) {
            continue;
        }

        if let Some(register) = handler.exception_register {
            registers[usize::from(register.0)] = exception.value;
        }
        return Ok(handler.target);
    }

    Err(VmError::UnhandledException {
        type_name: exception.type_name,
    })
}

fn handler_matches(handler: Option<&str>, actual: Option<&str>) -> bool {
    match handler {
        None => true,
        Some(expected) => actual == Some(expected),
    }
}
