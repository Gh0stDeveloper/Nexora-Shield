use crate::cfg::ControlFlowGraph;
use crate::error::{DexError, Result};
use crate::model::{CodeItem, DexFile, EncodedMethod, Instruction, ACC_STATIC};
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterType {
    Unknown,
    IntLike,
    Wide,
    Reference,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockTypeState {
    pub block_start: u32,
    pub entry: Vec<RegisterType>,
    pub exit: Vec<RegisterType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeAnalysis {
    pub method_idx: u32,
    pub blocks: Vec<BlockTypeState>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TypeAnalyzer;

impl TypeAnalyzer {
    pub fn analyze(dex: &DexFile, method_idx: u32) -> Result<TypeAnalysis> {
        let encoded = dex
            .encoded_method(method_idx)
            .ok_or(DexError::InvalidIndex {
                kind: "encoded method",
                index: method_idx,
            })?;
        let code =
            dex.code_items
                .get(&encoded.code_off)
                .ok_or_else(|| DexError::InvalidInstruction {
                    offset: 0,
                    reason: format!("method {method_idx} does not have a code_item"),
                })?;
        let cfg = ControlFlowGraph::build(code)?;
        if cfg.blocks.is_empty() {
            return Ok(TypeAnalysis {
                method_idx,
                blocks: Vec::new(),
            });
        }

        let mut initial = vec![RegisterType::Unknown; usize::from(code.registers_size)];
        seed_parameters(dex, method_idx, encoded, code, &mut initial)?;

        let mut entries = BTreeMap::<u32, Vec<RegisterType>>::new();
        let mut exits = BTreeMap::<u32, Vec<RegisterType>>::new();
        entries.insert(cfg.entry, initial);
        let mut queue = VecDeque::from([cfg.entry]);

        while let Some(block_start) = queue.pop_front() {
            let block = cfg.block(block_start).ok_or(DexError::InvalidControlFlow {
                offset: block_start,
                target: i64::from(block_start),
            })?;
            let mut state = entries
                .get(&block_start)
                .cloned()
                .unwrap_or_else(|| vec![RegisterType::Unknown; usize::from(code.registers_size)]);

            for offset in &block.instruction_offsets {
                let instruction = code
                    .instructions
                    .iter()
                    .find(|instruction| instruction.offset == *offset)
                    .ok_or(DexError::InvalidInstruction {
                        offset: *offset,
                        reason: "instruction is missing from code_item".into(),
                    })?;
                validate_registers(code, instruction)?;
                apply_transfer(code, instruction, &mut state)?;
            }

            let exit_changed = exits.get(&block_start) != Some(&state);
            exits.insert(block_start, state.clone());
            if !exit_changed {
                continue;
            }

            for successor in block
                .successors
                .iter()
                .chain(block.exception_successors.iter())
            {
                let changed = merge_entry(
                    entries.entry(*successor).or_insert_with(|| {
                        vec![RegisterType::Unknown; usize::from(code.registers_size)]
                    }),
                    &state,
                );
                if changed {
                    queue.push_back(*successor);
                }
            }
        }

        let blocks = cfg
            .blocks
            .iter()
            .map(|block| BlockTypeState {
                block_start: block.start,
                entry: entries.get(&block.start).cloned().unwrap_or_else(|| {
                    vec![RegisterType::Unknown; usize::from(code.registers_size)]
                }),
                exit: exits.get(&block.start).cloned().unwrap_or_else(|| {
                    vec![RegisterType::Unknown; usize::from(code.registers_size)]
                }),
            })
            .collect();

        Ok(TypeAnalysis { method_idx, blocks })
    }
}

fn seed_parameters(
    dex: &DexFile,
    method_idx: u32,
    encoded: &EncodedMethod,
    code: &CodeItem,
    state: &mut [RegisterType],
) -> Result<()> {
    let method = dex
        .methods
        .get(method_idx as usize)
        .ok_or(DexError::InvalidIndex {
            kind: "method",
            index: method_idx,
        })?;
    let proto = dex
        .protos
        .get(method.proto_idx as usize)
        .ok_or(DexError::InvalidIndex {
            kind: "proto",
            index: u32::from(method.proto_idx),
        })?;

    let mut register = usize::from(code.registers_size - code.ins_size);
    if encoded.access_flags & ACC_STATIC == 0 {
        if let Some(slot) = state.get_mut(register) {
            *slot = RegisterType::Reference;
        }
        register += 1;
    }

    for type_index in &proto.parameters {
        let descriptor =
            dex.type_descriptor(u32::from(*type_index))
                .ok_or(DexError::InvalidIndex {
                    kind: "type",
                    index: u32::from(*type_index),
                })?;
        let kind = descriptor_type(descriptor);
        let slot = state
            .get_mut(register)
            .ok_or(DexError::InvalidInstruction {
                offset: 0,
                reason: "parameter registers exceed registers_size".into(),
            })?;
        *slot = kind;
        if kind == RegisterType::Wide {
            register += 1;
            let high = state
                .get_mut(register)
                .ok_or(DexError::InvalidInstruction {
                    offset: 0,
                    reason: "wide parameter exceeds registers_size".into(),
                })?;
            *high = RegisterType::Wide;
        }
        register += 1;
    }

    Ok(())
}

fn descriptor_type(descriptor: &str) -> RegisterType {
    match descriptor.as_bytes().first().copied() {
        Some(b'L' | b'[') => RegisterType::Reference,
        Some(b'J' | b'D') => RegisterType::Wide,
        Some(_) => RegisterType::IntLike,
        None => RegisterType::Conflict,
    }
}

fn merge_entry(current: &mut [RegisterType], incoming: &[RegisterType]) -> bool {
    let mut changed = false;
    for (slot, value) in current.iter_mut().zip(incoming.iter().copied()) {
        let merged = merge_type(*slot, value);
        if merged != *slot {
            *slot = merged;
            changed = true;
        }
    }
    changed
}

fn merge_type(left: RegisterType, right: RegisterType) -> RegisterType {
    if left == right {
        left
    } else if left == RegisterType::Unknown {
        right
    } else if right == RegisterType::Unknown {
        left
    } else {
        RegisterType::Conflict
    }
}

fn apply_transfer(
    code: &CodeItem,
    instruction: &Instruction,
    state: &mut [RegisterType],
) -> Result<()> {
    let access = register_accesses(code, instruction)?;

    match instruction.opcode {
        0x01..=0x09 => {
            if let (Some(destination), Some(source)) = (access.defs.first(), access.uses.first()) {
                state[*destination as usize] = state[*source as usize];
            }
        }
        0x12..=0x15 | 0x20 | 0x21 | 0x2d..=0x31 | 0x90..=0xe2 => {
            for destination in &access.defs {
                state[*destination as usize] = RegisterType::IntLike;
            }
        }
        0x16..=0x19 => {
            for destination in &access.defs {
                state[*destination as usize] = RegisterType::Wide;
            }
        }
        0x1a..=0x1c | 0x22 | 0x23 => {
            for destination in &access.defs {
                state[*destination as usize] = RegisterType::Reference;
            }
        }
        0x1f => {
            if let Some(destination) = access.defs.first() {
                state[*destination as usize] = RegisterType::Reference;
            }
        }
        _ => {
            for destination in &access.defs {
                state[*destination as usize] = RegisterType::Unknown;
            }
        }
    }
    Ok(())
}

fn validate_registers(code: &CodeItem, instruction: &Instruction) -> Result<()> {
    let access = register_accesses(code, instruction)?;
    for register in access.defs.iter().chain(access.uses.iter()) {
        if *register >= code.registers_size {
            return Err(DexError::InvalidInstruction {
                offset: instruction.offset,
                reason: format!(
                    "register v{register} exceeds registers_size {}",
                    code.registers_size
                ),
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegisterAccess {
    pub defs: Vec<u16>,
    pub uses: Vec<u16>,
}

pub(crate) fn register_accesses(
    code: &CodeItem,
    instruction: &Instruction,
) -> Result<RegisterAccess> {
    if instruction.is_payload() {
        return Ok(RegisterAccess {
            defs: Vec::new(),
            uses: Vec::new(),
        });
    }

    let offset = instruction.offset as usize;
    let first = *code.insns.get(offset).ok_or(DexError::InvalidInstruction {
        offset: instruction.offset,
        reason: "missing first code unit".into(),
    })?;
    let a4 = (first >> 8) & 0x0f;
    let b4 = (first >> 12) & 0x0f;
    let a8 = first >> 8;
    let unit1 = || -> Result<u16> {
        code.insns
            .get(offset + 1)
            .copied()
            .ok_or(DexError::InvalidInstruction {
                offset: instruction.offset,
                reason: "missing second code unit".into(),
            })
    };
    let unit2 = || -> Result<u16> {
        code.insns
            .get(offset + 2)
            .copied()
            .ok_or(DexError::InvalidInstruction {
                offset: instruction.offset,
                reason: "missing third code unit".into(),
            })
    };

    let access = match instruction.opcode {
        0x01 | 0x04 | 0x07 | 0x20 | 0x21 | 0x23 | 0x52..=0x58 | 0x7b..=0x8f
        | 0xd0..=0xd7 => RegisterAccess {
            defs: vec![a4],
            uses: vec![b4],
        },
        0x02 | 0x05 | 0x08 => RegisterAccess {
            defs: vec![a8],
            uses: vec![unit1()?],
        },
        0x03 | 0x06 | 0x09 => RegisterAccess {
            defs: vec![unit1()?],
            uses: vec![unit2()?],
        },
        0x0a..=0x0d | 0x13..=0x1c | 0x22 | 0x60..=0x66 | 0xfe | 0xff => RegisterAccess {
            defs: vec![a8],
            uses: Vec::new(),
        },
        0x0f..=0x11 | 0x1d | 0x1e | 0x26 | 0x27 | 0x2b | 0x2c | 0x38..=0x3d
        | 0x67..=0x6d => RegisterAccess {
            defs: Vec::new(),
            uses: vec![a8],
        },
        0x12 => RegisterAccess {
            defs: vec![a4],
            uses: Vec::new(),
        },
        0x1f => RegisterAccess {
            defs: vec![a8],
            uses: vec![a8],
        },
        0x24 | 0x6e..=0x72 | 0xfa | 0xfc => RegisterAccess {
            defs: Vec::new(),
            uses: invoke_35c_registers(code, instruction.offset)?,
        },
        0x25 | 0x74..=0x78 | 0xfb | 0xfd => RegisterAccess {
            defs: Vec::new(),
            uses: invoke_range_registers(code, instruction.offset)?,
        },
        0x2d..=0x31 | 0x44..=0x4a | 0x90..=0xaf => {
            let second = unit1()?;
            RegisterAccess {
                defs: vec![a8],
                uses: vec![second & 0x00ff, second >> 8],
            }
        }
        0x32..=0x37 | 0x59..=0x5f => RegisterAccess {
            defs: Vec::new(),
            uses: vec![a4, b4],
        },
        0x4b..=0x51 => {
            let second = unit1()?;
            RegisterAccess {
                defs: Vec::new(),
                uses: vec![a8, second & 0x00ff, second >> 8],
            }
        }
        0xb0..=0xcf => RegisterAccess {
            defs: vec![a4],
            uses: vec![a4, b4],
        },
        0xd8..=0xe2 => {
            let second = unit1()?;
            RegisterAccess {
                defs: vec![a8],
                uses: vec![second & 0x00ff],
            }
        }
        _ => RegisterAccess {
            defs: Vec::new(),
            uses: Vec::new(),
        },
    };

    Ok(access)
}

fn invoke_35c_registers(code: &CodeItem, instruction_offset: u32) -> Result<Vec<u16>> {
    let offset = instruction_offset as usize;
    let first = code.insns[offset];
    let count = usize::from((first >> 12) & 0x0f);
    if count > 5 {
        return Err(DexError::InvalidInstruction {
            offset: instruction_offset,
            reason: format!("35c register count {count} exceeds 5"),
        });
    }
    let third = *code
        .insns
        .get(offset + 2)
        .ok_or(DexError::InvalidInstruction {
            offset: instruction_offset,
            reason: "truncated 35c instruction".into(),
        })?;
    let registers = [
        third & 0x000f,
        (third >> 4) & 0x000f,
        (third >> 8) & 0x000f,
        (third >> 12) & 0x000f,
        (first >> 8) & 0x000f,
    ];
    Ok(registers[..count].to_vec())
}

fn invoke_range_registers(code: &CodeItem, instruction_offset: u32) -> Result<Vec<u16>> {
    let offset = instruction_offset as usize;
    let first = code.insns[offset];
    let count = usize::from(first >> 8);
    let start = *code
        .insns
        .get(offset + 2)
        .ok_or(DexError::InvalidInstruction {
            offset: instruction_offset,
            reason: "truncated range instruction".into(),
        })?;
    let end = u32::from(start)
        .checked_add(count as u32)
        .ok_or(DexError::InvalidInstruction {
            offset: instruction_offset,
            reason: "range register overflow".into(),
        })?;
    if end > u32::from(u16::MAX) + 1 {
        return Err(DexError::InvalidInstruction {
            offset: instruction_offset,
            reason: "range register exceeds u16".into(),
        });
    }
    Ok((0..count).map(|delta| start + delta as u16).collect())
}
