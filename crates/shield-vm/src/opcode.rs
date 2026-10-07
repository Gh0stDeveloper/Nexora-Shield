use crate::error::{Result, VmError};
use crate::ir::VmInstruction;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticOpcode {
    Nop,
    LoadConst,
    Move,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Neg,
    Jump,
    Branch,
    LoadField,
    StoreField,
    Call,
    Throw,
    Return,
    ReturnVoid,
}

pub const ALL_SEMANTIC_OPCODES: [SemanticOpcode; 20] = [
    SemanticOpcode::Nop,
    SemanticOpcode::LoadConst,
    SemanticOpcode::Move,
    SemanticOpcode::Add,
    SemanticOpcode::Sub,
    SemanticOpcode::Mul,
    SemanticOpcode::Div,
    SemanticOpcode::Rem,
    SemanticOpcode::And,
    SemanticOpcode::Or,
    SemanticOpcode::Xor,
    SemanticOpcode::Neg,
    SemanticOpcode::Jump,
    SemanticOpcode::Branch,
    SemanticOpcode::LoadField,
    SemanticOpcode::StoreField,
    SemanticOpcode::Call,
    SemanticOpcode::Throw,
    SemanticOpcode::Return,
    SemanticOpcode::ReturnVoid,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcodeAllocation {
    build_id: String,
    encode: BTreeMap<SemanticOpcode, u8>,
    decode: BTreeMap<u8, SemanticOpcode>,
    fingerprint: [u8; 32],
}

impl OpcodeAllocation {
    pub fn derive(build_id: &str, private_seed: &[u8]) -> Result<Self> {
        if build_id.trim().is_empty() {
            return Err(VmError::EmptyBuildId);
        }
        if private_seed.is_empty() {
            return Err(VmError::EmptySeed);
        }

        let mut pool = (1_u16..=255)
            .filter_map(|value| u8::try_from(value).ok())
            .collect::<Vec<_>>();

        for index in (1..pool.len()).rev() {
            let selector = allocation_selector(build_id, private_seed, index);
            let swap_with = usize::from(selector) % (index + 1);
            pool.swap(index, swap_with);
        }

        let mut encode = BTreeMap::new();
        let mut decode = BTreeMap::new();
        for (semantic, encoded) in ALL_SEMANTIC_OPCODES.iter().copied().zip(pool) {
            encode.insert(semantic, encoded);
            decode.insert(encoded, semantic);
        }

        let fingerprint = allocation_fingerprint(&encode);
        Ok(Self {
            build_id: build_id.to_owned(),
            encode,
            decode,
            fingerprint,
        })
    }

    pub fn encode(&self, semantic: SemanticOpcode) -> Result<u8> {
        self.encode
            .get(&semantic)
            .copied()
            .ok_or(VmError::InvalidOpcode(0))
    }

    pub fn decode(&self, opcode: u8) -> Result<SemanticOpcode> {
        self.decode
            .get(&opcode)
            .copied()
            .ok_or(VmError::InvalidOpcode(opcode))
    }

    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    #[must_use]
    pub fn build_id(&self) -> &str {
        &self.build_id
    }

    #[must_use]
    pub fn same_assignments(&self, other: &Self) -> usize {
        ALL_SEMANTIC_OPCODES
            .iter()
            .filter(|semantic| self.encode.get(semantic) == other.encode.get(semantic))
            .count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcodeStream {
    pub bytes: Vec<u8>,
}

impl OpcodeStream {
    pub fn encode(
        instructions: &[VmInstruction],
        allocation: &OpcodeAllocation,
    ) -> Result<Self> {
        let bytes = instructions
            .iter()
            .map(|instruction| allocation.encode(semantic_opcode(instruction)))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { bytes })
    }

    pub fn semantics(&self, allocation: &OpcodeAllocation) -> Result<Vec<SemanticOpcode>> {
        self.bytes
            .iter()
            .copied()
            .map(|opcode| allocation.decode(opcode))
            .collect()
    }
}

#[must_use]
pub fn semantic_opcode(instruction: &VmInstruction) -> SemanticOpcode {
    match instruction {
        VmInstruction::Nop => SemanticOpcode::Nop,
        VmInstruction::LoadConst { .. } => SemanticOpcode::LoadConst,
        VmInstruction::Move { .. } => SemanticOpcode::Move,
        VmInstruction::Add { .. } => SemanticOpcode::Add,
        VmInstruction::Sub { .. } => SemanticOpcode::Sub,
        VmInstruction::Mul { .. } => SemanticOpcode::Mul,
        VmInstruction::Div { .. } => SemanticOpcode::Div,
        VmInstruction::Rem { .. } => SemanticOpcode::Rem,
        VmInstruction::And { .. } => SemanticOpcode::And,
        VmInstruction::Or { .. } => SemanticOpcode::Or,
        VmInstruction::Xor { .. } => SemanticOpcode::Xor,
        VmInstruction::Neg { .. } => SemanticOpcode::Neg,
        VmInstruction::Jump { .. } => SemanticOpcode::Jump,
        VmInstruction::Branch { .. } => SemanticOpcode::Branch,
        VmInstruction::LoadField { .. } => SemanticOpcode::LoadField,
        VmInstruction::StoreField { .. } => SemanticOpcode::StoreField,
        VmInstruction::Call { .. } => SemanticOpcode::Call,
        VmInstruction::Throw { .. } => SemanticOpcode::Throw,
        VmInstruction::Return { .. } => SemanticOpcode::Return,
        VmInstruction::ReturnVoid => SemanticOpcode::ReturnVoid,
    }
}

fn allocation_selector(build_id: &str, seed: &[u8], index: usize) -> u16 {
    let mut hasher = Sha256::new();
    hasher.update(b"nexora-shield/vm-opcode-allocation/v1");
    hasher.update((build_id.len() as u64).to_le_bytes());
    hasher.update(build_id.as_bytes());
    hasher.update((seed.len() as u64).to_le_bytes());
    hasher.update(seed);
    hasher.update((index as u64).to_le_bytes());
    let digest = hasher.finalize();
    u16::from_le_bytes([digest[0], digest[1]])
}

fn allocation_fingerprint(encode: &BTreeMap<SemanticOpcode, u8>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"nexora-shield/vm-opcode-fingerprint/v1");
    for semantic in ALL_SEMANTIC_OPCODES {
        if let Some(value) = encode.get(&semantic) {
            hasher.update([*value]);
        }
    }
    hasher.finalize().into()
}
