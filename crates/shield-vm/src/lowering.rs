use crate::constant_pool::{ConstantPool, VmConstant};
use crate::eligibility::{EligibilityAnalyzer, EligibilityPolicy};
use crate::error::{Result, VmError};
use crate::ir::{
    BranchCondition, VmExceptionHandler, VmInstruction, VmMethod, VmRegister,
};
use nexora_shield_dex::{CodeItem, DexFile, Instruction, IrMethod, ReferenceKind};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, Clone, Copy)]
pub struct DexLowerer;

impl DexLowerer {
    pub fn lower(
        dex: &DexFile,
        method_idx: u32,
        policy: EligibilityPolicy,
    ) -> Result<VmMethod> {
        let report = EligibilityAnalyzer::analyze(dex, method_idx, policy);
        if !report.eligible {
            return Err(VmError::IneligibleMethod {
                method_idx,
                reason: format!("{:?}", report.reasons),
            });
        }

        IrMethod::build(dex, method_idx).map_err(|error| VmError::IneligibleMethod {
            method_idx,
            reason: error.to_string(),
        })?;

        let code = dex
            .code_for_method(method_idx)
            .ok_or(VmError::IneligibleMethod {
                method_idx,
                reason: "missing code_item".to_owned(),
            })?;

        let executable = code
            .instructions
            .iter()
            .filter(|instruction| !instruction.is_payload())
            .collect::<Vec<_>>();
        let handler_targets = exception_handler_targets(code);
        let (skip_offsets, call_destinations) =
            collect_compound_instruction_metadata(code, &executable, &handler_targets)?;

        let mut offset_to_pc = BTreeMap::<u32, usize>::new();
        let mut pc = 0_usize;
        for instruction in &executable {
            offset_to_pc.insert(instruction.offset, pc);
            if !skip_offsets.contains(&instruction.offset) {
                pc = pc.saturating_add(1);
            }
        }
        offset_to_pc.insert(code.insns_size, pc);

        let mut constants = ConstantPool::default();
        let mut instructions = Vec::with_capacity(pc);
        for instruction in executable {
            if skip_offsets.contains(&instruction.offset) {
                continue;
            }
            instructions.push(lower_instruction(
                dex,
                code,
                instruction,
                &offset_to_pc,
                &call_destinations,
                &mut constants,
            )?);
        }

        let handlers = lower_handlers(dex, code, &offset_to_pc)?;
        let parameter_start = code.registers_size.saturating_sub(code.ins_size);
        let parameter_registers = (parameter_start..code.registers_size)
            .map(VmRegister)
            .collect::<Vec<_>>();

        let method = VmMethod {
            method_idx,
            register_count: code.registers_size,
            parameter_registers,
            instructions,
            constants,
            handlers,
        };
        method.validate()?;
        Ok(method)
    }
}

fn collect_compound_instruction_metadata(
    code: &CodeItem,
    executable: &[&Instruction],
    handler_targets: &BTreeSet<u32>,
) -> Result<(BTreeSet<u32>, BTreeMap<u32, Option<VmRegister>>)> {
    let mut skip_offsets = BTreeSet::new();
    let mut call_destinations = BTreeMap::new();

    for (index, instruction) in executable.iter().enumerate() {
        if handler_targets.contains(&instruction.offset) && instruction.opcode == 0x0d {
            skip_offsets.insert(instruction.offset);
        }

        if !matches!(instruction.opcode, 0x6e..=0x72 | 0x74..=0x78) {
            continue;
        }

        let next = executable.get(index + 1).copied();
        let destination = match next {
            Some(next) if matches!(next.opcode, 0x0a | 0x0c) => {
                skip_offsets.insert(next.offset);
                Some(VmRegister(register_a8(code, next.offset)?))
            }
            Some(next) if next.opcode == 0x0b => {
                return Err(VmError::UnsupportedDexOpcode {
                    offset: next.offset,
                    opcode: next.opcode,
                });
            }
            _ => None,
        };
        call_destinations.insert(instruction.offset, destination);
    }

    Ok((skip_offsets, call_destinations))
}

fn lower_instruction(
    dex: &DexFile,
    code: &CodeItem,
    instruction: &Instruction,
    offset_to_pc: &BTreeMap<u32, usize>,
    call_destinations: &BTreeMap<u32, Option<VmRegister>>,
    constants: &mut ConstantPool,
) -> Result<VmInstruction> {
    let first = code_unit(code, instruction.offset)?;
    let a4 = VmRegister((first >> 8) & 0x0f);
    let b4 = VmRegister((first >> 12) & 0x0f);
    let a8 = VmRegister(first >> 8);

    match instruction.opcode {
        0x00 => Ok(VmInstruction::Nop),
        0x01 | 0x07 => Ok(VmInstruction::Move {
            dst: a4,
            src: b4,
        }),
        0x02 | 0x08 => Ok(VmInstruction::Move {
            dst: a8,
            src: VmRegister(code_unit(code, instruction.offset + 1)?),
        }),
        0x03 | 0x09 => Ok(VmInstruction::Move {
            dst: VmRegister(code_unit(code, instruction.offset + 1)?),
            src: VmRegister(code_unit(code, instruction.offset + 2)?),
        }),
        0x0e => Ok(VmInstruction::ReturnVoid),
        0x0f | 0x11 => Ok(VmInstruction::Return { src: a8 }),
        0x12..=0x15 => {
            let value = decode_int_constant(code, instruction)?;
            let constant = constants.intern(VmConstant::Int(value))?;
            Ok(VmInstruction::LoadConst { dst: a8_or_a4(instruction.opcode, a8, a4), constant })
        }
        0x1a | 0x1b => {
            let index = reference_index(instruction, ReferenceKind::String, "string")?;
            let value = dex.string(index).ok_or(VmError::InvalidDexReference {
                offset: instruction.offset,
                expected: "valid string",
            })?;
            let constant = constants.intern(VmConstant::String(value.to_owned()))?;
            Ok(VmInstruction::LoadConst { dst: a8, constant })
        }
        0x1c => {
            let index = reference_index(instruction, ReferenceKind::Type, "type")?;
            let value = dex
                .type_descriptor(index)
                .ok_or(VmError::InvalidDexReference {
                    offset: instruction.offset,
                    expected: "valid type",
                })?;
            let constant = constants.intern(VmConstant::Type(value.to_owned()))?;
            Ok(VmInstruction::LoadConst { dst: a8, constant })
        }
        0x27 => Ok(VmInstruction::Throw { src: a8 }),
        0x28..=0x2a => Ok(VmInstruction::Jump {
            target: branch_target(instruction, offset_to_pc)?,
        }),
        0x32..=0x37 => Ok(VmInstruction::Branch {
            condition: binary_branch_condition(instruction.opcode),
            left: a4,
            right: Some(b4),
            target: branch_target(instruction, offset_to_pc)?,
        }),
        0x38..=0x3d => Ok(VmInstruction::Branch {
            condition: zero_branch_condition(instruction.opcode),
            left: a8,
            right: None,
            target: branch_target(instruction, offset_to_pc)?,
        }),
        0x52..=0x58 => Ok(VmInstruction::LoadField {
            dst: a4,
            object: Some(b4),
            field: reference_index(instruction, ReferenceKind::Field, "field")?,
        }),
        0x59..=0x5f => Ok(VmInstruction::StoreField {
            object: Some(b4),
            field: reference_index(instruction, ReferenceKind::Field, "field")?,
            src: a4,
        }),
        0x60..=0x66 => Ok(VmInstruction::LoadField {
            dst: a8,
            object: None,
            field: reference_index(instruction, ReferenceKind::Field, "field")?,
        }),
        0x67..=0x6d => Ok(VmInstruction::StoreField {
            object: None,
            field: reference_index(instruction, ReferenceKind::Field, "field")?,
            src: a8,
        }),
        0x6e..=0x72 => Ok(VmInstruction::Call {
            dst: call_destinations
                .get(&instruction.offset)
                .copied()
                .flatten(),
            method: reference_index(instruction, ReferenceKind::Method, "method")?,
            args: invoke_35c_registers(code, instruction.offset)?,
        }),
        0x74..=0x78 => Ok(VmInstruction::Call {
            dst: call_destinations
                .get(&instruction.offset)
                .copied()
                .flatten(),
            method: reference_index(instruction, ReferenceKind::Method, "method")?,
            args: invoke_range_registers(code, instruction.offset)?,
        }),
        0x7b => Ok(VmInstruction::Neg {
            dst: a4,
            src: b4,
        }),
        0x90..=0x97 => {
            let second = code_unit(code, instruction.offset + 1)?;
            let left = VmRegister(second & 0x00ff);
            let right = VmRegister(second >> 8);
            lower_binary(instruction.opcode, a8, left, right)
        }
        0xb0..=0xb7 => lower_binary(instruction.opcode, a4, a4, b4),
        opcode => Err(VmError::UnsupportedDexOpcode {
            offset: instruction.offset,
            opcode,
        }),
    }
}

fn lower_binary(
    opcode: u8,
    dst: VmRegister,
    left: VmRegister,
    right: VmRegister,
) -> Result<VmInstruction> {
    let normalized = if (0xb0..=0xb7).contains(&opcode) {
        opcode - 0x20
    } else {
        opcode
    };
    let instruction = match normalized {
        0x90 => VmInstruction::Add { dst, left, right },
        0x91 => VmInstruction::Sub { dst, left, right },
        0x92 => VmInstruction::Mul { dst, left, right },
        0x93 => VmInstruction::Div { dst, left, right },
        0x94 => VmInstruction::Rem { dst, left, right },
        0x95 => VmInstruction::And { dst, left, right },
        0x96 => VmInstruction::Or { dst, left, right },
        0x97 => VmInstruction::Xor { dst, left, right },
        _ => {
            return Err(VmError::UnsupportedDexOpcode {
                offset: 0,
                opcode,
            });
        }
    };
    Ok(instruction)
}

fn lower_handlers(
    dex: &DexFile,
    code: &CodeItem,
    offset_to_pc: &BTreeMap<u32, usize>,
) -> Result<Vec<VmExceptionHandler>> {
    let mut result = Vec::new();
    for try_item in &code.tries {
        let start_offset = try_item.start_addr;
        let end_offset = try_item
            .start_addr
            .saturating_add(u32::from(try_item.insn_count));
        let start = pc_for_offset(offset_to_pc, start_offset, start_offset)?;
        let end = pc_for_offset(offset_to_pc, end_offset, start_offset)?;
        let handler = code
            .handlers
            .iter()
            .find(|candidate| candidate.relative_offset == u32::from(try_item.handler_off))
            .ok_or(VmError::InvalidHandler { target: start })?;

        for (type_index, target_offset) in &handler.typed_handlers {
            let type_name = dex
                .type_descriptor(*type_index)
                .ok_or(VmError::InvalidDexReference {
                    offset: *target_offset,
                    expected: "exception type",
                })?
                .to_owned();
            result.push(VmExceptionHandler {
                start,
                end,
                target: pc_for_offset(offset_to_pc, *target_offset, start_offset)?,
                type_name: Some(type_name),
                exception_register: exception_register(code, *target_offset)?,
            });
        }

        if let Some(target_offset) = handler.catch_all_addr {
            result.push(VmExceptionHandler {
                start,
                end,
                target: pc_for_offset(offset_to_pc, target_offset, start_offset)?,
                type_name: None,
                exception_register: exception_register(code, target_offset)?,
            });
        }
    }
    Ok(result)
}

fn exception_handler_targets(code: &CodeItem) -> BTreeSet<u32> {
    code.handlers
        .iter()
        .flat_map(|handler| {
            handler
                .typed_handlers
                .iter()
                .map(|(_, target)| *target)
                .chain(handler.catch_all_addr)
        })
        .collect()
}

fn exception_register(code: &CodeItem, target_offset: u32) -> Result<Option<VmRegister>> {
    let instruction = code
        .instructions
        .iter()
        .find(|instruction| instruction.offset == target_offset && !instruction.is_payload());
    match instruction {
        Some(instruction) if instruction.opcode == 0x0d => {
            Ok(Some(VmRegister(register_a8(code, target_offset)?)))
        }
        _ => Ok(None),
    }
}

fn decode_int_constant(code: &CodeItem, instruction: &Instruction) -> Result<i32> {
    let first = code_unit(code, instruction.offset)?;
    match instruction.opcode {
        0x12 => {
            let literal = (first >> 12) & 0x0f;
            Ok(if literal & 0x08 == 0 {
                i32::from(literal)
            } else {
                i32::from(literal) - 16
            })
        }
        0x13 => {
            let raw = code_unit(code, instruction.offset + 1)?;
            Ok(i32::from(i16::from_le_bytes(raw.to_le_bytes())))
        }
        0x14 => {
            let low = code_unit(code, instruction.offset + 1)?;
            let high = code_unit(code, instruction.offset + 2)?;
            let raw = u32::from(low) | (u32::from(high) << 16);
            Ok(i32::from_le_bytes(raw.to_le_bytes()))
        }
        0x15 => {
            let raw = code_unit(code, instruction.offset + 1)?;
            Ok(i32::from(i16::from_le_bytes(raw.to_le_bytes())) << 16)
        }
        opcode => Err(VmError::UnsupportedDexOpcode {
            offset: instruction.offset,
            opcode,
        }),
    }
}

fn a8_or_a4(opcode: u8, a8: VmRegister, a4: VmRegister) -> VmRegister {
    if opcode == 0x12 {
        a4
    } else {
        a8
    }
}

fn reference_index(
    instruction: &Instruction,
    expected: ReferenceKind,
    label: &'static str,
) -> Result<u32> {
    match instruction.reference {
        Some((kind, index)) if kind == expected => Ok(index),
        _ => Err(VmError::InvalidDexReference {
            offset: instruction.offset,
            expected: label,
        }),
    }
}

fn branch_target(
    instruction: &Instruction,
    offset_to_pc: &BTreeMap<u32, usize>,
) -> Result<usize> {
    let target = instruction
        .branch_targets
        .first()
        .copied()
        .ok_or(VmError::InvalidJump {
            from: usize::try_from(instruction.offset).unwrap_or(usize::MAX),
            target: usize::MAX,
        })?;
    pc_for_offset(offset_to_pc, target, instruction.offset)
}

fn pc_for_offset(
    offset_to_pc: &BTreeMap<u32, usize>,
    target: u32,
    from: u32,
) -> Result<usize> {
    offset_to_pc
        .get(&target)
        .copied()
        .ok_or(VmError::InvalidJump {
            from: usize::try_from(from).unwrap_or(usize::MAX),
            target: usize::try_from(target).unwrap_or(usize::MAX),
        })
}

const fn binary_branch_condition(opcode: u8) -> BranchCondition {
    match opcode {
        0x32 => BranchCondition::Eq,
        0x33 => BranchCondition::Ne,
        0x34 => BranchCondition::Lt,
        0x35 => BranchCondition::Ge,
        0x36 => BranchCondition::Gt,
        _ => BranchCondition::Le,
    }
}

const fn zero_branch_condition(opcode: u8) -> BranchCondition {
    match opcode {
        0x38 => BranchCondition::EqZero,
        0x39 => BranchCondition::NeZero,
        0x3a => BranchCondition::LtZero,
        0x3b => BranchCondition::GeZero,
        0x3c => BranchCondition::GtZero,
        _ => BranchCondition::LeZero,
    }
}

fn invoke_35c_registers(code: &CodeItem, offset: u32) -> Result<Vec<VmRegister>> {
    let first = code_unit(code, offset)?;
    let count = usize::from((first >> 12) & 0x0f);
    if count > 5 {
        return Err(VmError::UnsupportedDexOpcode {
            offset,
            opcode: u8::try_from(first & 0x00ff).unwrap_or(0xff),
        });
    }
    let third = code_unit(code, offset + 2)?;
    let registers = [
        VmRegister(third & 0x000f),
        VmRegister((third >> 4) & 0x000f),
        VmRegister((third >> 8) & 0x000f),
        VmRegister((third >> 12) & 0x000f),
        VmRegister((first >> 8) & 0x000f),
    ];
    Ok(registers[..count].to_vec())
}

fn invoke_range_registers(code: &CodeItem, offset: u32) -> Result<Vec<VmRegister>> {
    let first = code_unit(code, offset)?;
    let count = usize::from(first >> 8);
    let start = code_unit(code, offset + 2)?;
    (0..count)
        .map(|delta| {
            let delta = u16::try_from(delta).map_err(|_| VmError::InvalidRegister(u16::MAX))?;
            start
                .checked_add(delta)
                .map(VmRegister)
                .ok_or(VmError::InvalidRegister(u16::MAX))
        })
        .collect()
}

fn register_a8(code: &CodeItem, offset: u32) -> Result<u16> {
    Ok(code_unit(code, offset)? >> 8)
}

fn code_unit(code: &CodeItem, offset: u32) -> Result<u16> {
    code.insns
        .get(usize::try_from(offset).unwrap_or(usize::MAX))
        .copied()
        .ok_or(VmError::UnsupportedDexOpcode {
            offset,
            opcode: 0xff,
        })
}
