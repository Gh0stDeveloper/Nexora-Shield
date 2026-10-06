use crate::analysis::register_accesses;
use crate::cfg::ControlFlowGraph;
use crate::error::{DexError, Result};
use crate::model::{DexFile, ReferenceKind};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SsaValue {
    pub id: u32,
    pub register: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrPhi {
    pub register: u16,
    pub output: SsaValue,
    pub inputs: Vec<(u32, SsaValue)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrInstruction {
    pub offset: u32,
    pub opcode: u8,
    pub defs: Vec<SsaValue>,
    pub uses: Vec<SsaValue>,
    pub branch_targets: Vec<u32>,
    pub reference: Option<(ReferenceKind, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrBlock {
    pub start: u32,
    pub phis: Vec<IrPhi>,
    pub instructions: Vec<IrInstruction>,
    pub successors: Vec<u32>,
    pub exception_successors: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrMethod {
    pub method_idx: u32,
    pub register_count: u16,
    pub blocks: Vec<IrBlock>,
}

impl IrMethod {
    pub fn build(dex: &DexFile, method_idx: u32) -> Result<Self> {
        let code = dex
            .code_for_method(method_idx)
            .ok_or(DexError::InvalidIndex {
                kind: "code method",
                index: method_idx,
            })?;
        let cfg = ControlFlowGraph::build(code)?;
        let register_count = code.registers_size;

        let mut next_value_id = 1_u32;
        let mut base_values = Vec::with_capacity(usize::from(register_count));
        for register in 0..register_count {
            base_values.push(SsaValue {
                id: next_value_id,
                register,
            });
            next_value_id += 1;
        }

        let mut phi_ids = BTreeMap::<(u32, u16), SsaValue>::new();
        for block in &cfg.blocks {
            if block.start == cfg.entry || block.predecessors.is_empty() {
                continue;
            }
            for register in 0..register_count {
                phi_ids.insert(
                    (block.start, register),
                    SsaValue {
                        id: next_value_id,
                        register,
                    },
                );
                next_value_id += 1;
            }
        }

        let instruction_by_offset = code
            .instructions
            .iter()
            .filter(|instruction| !instruction.is_payload())
            .map(|instruction| (instruction.offset, instruction))
            .collect::<BTreeMap<_, _>>();

        let mut definition_ids = BTreeMap::<(u32, u16), SsaValue>::new();
        for instruction in code.instructions.iter().filter(|item| !item.is_payload()) {
            let access = register_accesses(code, instruction)?;
            for register in access.defs {
                definition_ids.insert(
                    (instruction.offset, register),
                    SsaValue {
                        id: next_value_id,
                        register,
                    },
                );
                next_value_id += 1;
            }
        }

        let mut exit_maps = BTreeMap::<u32, Vec<SsaValue>>::new();
        let mut blocks = Vec::with_capacity(cfg.blocks.len());

        for block in &cfg.blocks {
            let mut current = if block.start == cfg.entry || block.predecessors.is_empty() {
                base_values.clone()
            } else {
                (0..register_count)
                    .map(|register| {
                        phi_ids.get(&(block.start, register)).copied().ok_or(
                            DexError::InvalidControlFlow {
                                offset: block.start,
                                target: i64::from(block.start),
                            },
                        )
                    })
                    .collect::<Result<Vec<_>>>()?
            };

            let mut ir_instructions = Vec::with_capacity(block.instruction_offsets.len());
            for offset in &block.instruction_offsets {
                let instruction = instruction_by_offset.get(offset).copied().ok_or(
                    DexError::InvalidInstruction {
                        offset: *offset,
                        reason: "instruction missing while building IR".into(),
                    },
                )?;
                let access = register_accesses(code, instruction)?;
                let uses = access
                    .uses
                    .iter()
                    .map(|register| {
                        current.get(usize::from(*register)).copied().ok_or(
                            DexError::InvalidInstruction {
                                offset: *offset,
                                reason: format!("IR use register v{register} out of range"),
                            },
                        )
                    })
                    .collect::<Result<Vec<_>>>()?;

                let mut defs = Vec::with_capacity(access.defs.len());
                for register in access.defs {
                    let value = definition_ids.get(&(*offset, register)).copied().ok_or(
                        DexError::InvalidInstruction {
                            offset: *offset,
                            reason: "definition does not have an SSA value".into(),
                        },
                    )?;
                    current[usize::from(register)] = value;
                    defs.push(value);
                }

                ir_instructions.push(IrInstruction {
                    offset: *offset,
                    opcode: instruction.opcode,
                    defs,
                    uses,
                    branch_targets: instruction.branch_targets.clone(),
                    reference: instruction.reference,
                });
            }

            exit_maps.insert(block.start, current);
            blocks.push(IrBlock {
                start: block.start,
                phis: Vec::new(),
                instructions: ir_instructions,
                successors: block.successors.clone(),
                exception_successors: block.exception_successors.clone(),
            });
        }

        for ir_block in &mut blocks {
            let Some(cfg_block) = cfg.block(ir_block.start) else {
                continue;
            };
            if ir_block.start == cfg.entry || cfg_block.predecessors.is_empty() {
                continue;
            }

            for register in 0..register_count {
                let output = phi_ids.get(&(ir_block.start, register)).copied().ok_or(
                    DexError::InvalidControlFlow {
                        offset: ir_block.start,
                        target: i64::from(ir_block.start),
                    },
                )?;
                let mut inputs = Vec::with_capacity(cfg_block.predecessors.len());
                for predecessor in &cfg_block.predecessors {
                    let predecessor_exit =
                        exit_maps
                            .get(predecessor)
                            .ok_or(DexError::InvalidControlFlow {
                                offset: *predecessor,
                                target: i64::from(ir_block.start),
                            })?;
                    inputs.push((*predecessor, predecessor_exit[usize::from(register)]));
                }
                ir_block.phis.push(IrPhi {
                    register,
                    output,
                    inputs,
                });
            }
        }

        Ok(Self {
            method_idx,
            register_count,
            blocks,
        })
    }
}
