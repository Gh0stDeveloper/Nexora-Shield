use crate::error::{DexError, Result};
use crate::model::{CatchHandler, CodeItem, Instruction};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    pub start: u32,
    pub end: u32,
    pub instruction_offsets: Vec<u32>,
    pub predecessors: Vec<u32>,
    pub successors: Vec<u32>,
    pub exception_successors: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFlowGraph {
    pub entry: u32,
    pub blocks: Vec<BasicBlock>,
}

impl ControlFlowGraph {
    pub fn build(code: &CodeItem) -> Result<Self> {
        if code.instructions.is_empty() {
            return Ok(Self {
                entry: 0,
                blocks: Vec::new(),
            });
        }

        let executable = code
            .instructions
            .iter()
            .filter(|instruction| !instruction.is_payload())
            .map(|instruction| instruction.offset)
            .collect::<BTreeSet<_>>();

        let mut boundaries = BTreeSet::from([0_u32]);
        for instruction in &code.instructions {
            if instruction.is_payload() {
                continue;
            }
            for target in &instruction.branch_targets {
                require_executable(&executable, instruction.offset, *target)?;
                boundaries.insert(*target);
            }
            if instruction.falls_through()
                && (!instruction.branch_targets.is_empty() || is_conditional(instruction))
                && instruction.end_offset() < code.insns_size
            {
                boundaries.insert(instruction.end_offset());
            }
            if (instruction.is_return_or_throw() || instruction.is_unconditional_goto())
                && instruction.end_offset() < code.insns_size
                && executable.contains(&instruction.end_offset())
            {
                boundaries.insert(instruction.end_offset());
            }
        }

        for handler in &code.handlers {
            for target in handler_targets(handler) {
                require_executable(&executable, 0, target)?;
                boundaries.insert(target);
            }
        }

        let starts = boundaries.into_iter().collect::<Vec<_>>();
        let mut blocks = Vec::with_capacity(starts.len());
        for (index, start) in starts.iter().copied().enumerate() {
            let end = starts.get(index + 1).copied().unwrap_or(code.insns_size);
            let instruction_offsets = code
                .instructions
                .iter()
                .filter(|instruction| {
                    !instruction.is_payload()
                        && instruction.offset >= start
                        && instruction.offset < end
                })
                .map(|instruction| instruction.offset)
                .collect::<Vec<_>>();
            if instruction_offsets.is_empty() {
                continue;
            }
            blocks.push(BasicBlock {
                start,
                end,
                instruction_offsets,
                predecessors: Vec::new(),
                successors: Vec::new(),
                exception_successors: Vec::new(),
            });
        }

        let instruction_map = code
            .instructions
            .iter()
            .map(|instruction| (instruction.offset, instruction))
            .collect::<BTreeMap<_, _>>();

        for block_index in 0..blocks.len() {
            let last_offset = *blocks[block_index].instruction_offsets.last().ok_or(
                DexError::InvalidControlFlow {
                    offset: blocks[block_index].start,
                    target: i64::from(blocks[block_index].start),
                },
            )?;
            let last =
                instruction_map
                    .get(&last_offset)
                    .copied()
                    .ok_or(DexError::InvalidControlFlow {
                        offset: last_offset,
                        target: i64::from(last_offset),
                    })?;

            let mut successors = BTreeSet::new();
            for target in &last.branch_targets {
                let target_block =
                    find_block_start(&blocks, *target).ok_or(DexError::InvalidControlFlow {
                        offset: last.offset,
                        target: i64::from(*target),
                    })?;
                successors.insert(target_block);
            }
            if last.falls_through() {
                let next = last.end_offset();
                if next < code.insns_size && executable.contains(&next) {
                    let target_block =
                        find_block_start(&blocks, next).ok_or(DexError::InvalidControlFlow {
                            offset: last.offset,
                            target: i64::from(next),
                        })?;
                    successors.insert(target_block);
                }
            }

            let mut exception_targets = BTreeSet::new();
            for try_item in &code.tries {
                let try_end = try_item.start_addr + u32::from(try_item.insn_count);
                let block = &blocks[block_index];
                if block.start < try_end && block.end > try_item.start_addr {
                    if let Some(handler) = code
                        .handlers
                        .iter()
                        .find(|handler| handler.relative_offset == u32::from(try_item.handler_off))
                    {
                        for target in handler_targets(handler) {
                            if let Some(target_block) = find_block_start(&blocks, target) {
                                exception_targets.insert(target_block);
                            }
                        }
                    }
                }
            }

            blocks[block_index].successors = successors.into_iter().collect();
            blocks[block_index].exception_successors = exception_targets.into_iter().collect();
        }

        let mut predecessor_map = BTreeMap::<u32, BTreeSet<u32>>::new();
        for block in &blocks {
            for successor in block
                .successors
                .iter()
                .chain(block.exception_successors.iter())
            {
                predecessor_map
                    .entry(*successor)
                    .or_default()
                    .insert(block.start);
            }
        }
        for block in &mut blocks {
            block.predecessors = predecessor_map
                .remove(&block.start)
                .unwrap_or_default()
                .into_iter()
                .collect();
        }

        Ok(Self { entry: 0, blocks })
    }

    #[must_use]
    pub fn block(&self, start: u32) -> Option<&BasicBlock> {
        self.blocks.iter().find(|block| block.start == start)
    }
}

fn find_block_start(blocks: &[BasicBlock], target: u32) -> Option<u32> {
    blocks
        .iter()
        .find(|block| target >= block.start && target < block.end)
        .map(|block| block.start)
}

fn require_executable(executable: &BTreeSet<u32>, origin: u32, target: u32) -> Result<()> {
    if executable.contains(&target) {
        Ok(())
    } else {
        Err(DexError::InvalidControlFlow {
            offset: origin,
            target: i64::from(target),
        })
    }
}

fn handler_targets(handler: &CatchHandler) -> impl Iterator<Item = u32> + '_ {
    handler
        .typed_handlers
        .iter()
        .map(|(_, address)| *address)
        .chain(handler.catch_all_addr)
}

fn is_conditional(instruction: &Instruction) -> bool {
    matches!(instruction.opcode, 0x2b | 0x2c | 0x32..=0x3d)
}
