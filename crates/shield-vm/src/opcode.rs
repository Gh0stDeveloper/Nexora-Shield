use crate::error::{Result, VmError};
use crate::ir::{BranchCondition, VmInstruction, VmRegister};
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
    pub fn encode(instructions: &[VmInstruction], allocation: &OpcodeAllocation) -> Result<Self> {
        let mut writer = BytecodeWriter::default();
        for instruction in instructions {
            writer.u8(allocation.encode(semantic_opcode(instruction))?);
            encode_operands(&mut writer, instruction)?;
        }
        Ok(Self {
            bytes: writer.bytes,
        })
    }

    pub fn decode(&self, allocation: &OpcodeAllocation) -> Result<Vec<VmInstruction>> {
        let mut reader = BytecodeReader::new(&self.bytes);
        let mut instructions = Vec::new();
        while !reader.is_finished() {
            let opcode = reader.u8()?;
            let semantic = allocation.decode(opcode)?;
            instructions.push(decode_instruction(&mut reader, semantic)?);
        }
        Ok(instructions)
    }

    pub fn semantics(&self, allocation: &OpcodeAllocation) -> Result<Vec<SemanticOpcode>> {
        Ok(self
            .decode(allocation)?
            .iter()
            .map(semantic_opcode)
            .collect())
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes).into()
    }
}

#[derive(Debug, Default)]
struct BytecodeWriter {
    bytes: Vec<u8>,
}

impl BytecodeWriter {
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn register(&mut self, register: VmRegister) {
        self.u16(register.0);
    }

    fn optional_register(&mut self, register: Option<VmRegister>) {
        self.u16(register.map_or(u16::MAX, |value| value.0));
    }

    fn target(&mut self, target: usize) -> Result<()> {
        self.u32(
            u32::try_from(target)
                .map_err(|_| VmError::MalformedBytecode("jump target exceeds u32".to_owned()))?,
        );
        Ok(())
    }
}

struct BytecodeReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BytecodeReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn u8(&mut self) -> Result<u8> {
        let value = self
            .bytes
            .get(self.position)
            .copied()
            .ok_or_else(|| VmError::MalformedBytecode("unexpected end of stream".to_owned()))?;
        self.position = self.position.saturating_add(1);
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes = self.take::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn register(&mut self) -> Result<VmRegister> {
        Ok(VmRegister(self.u16()?))
    }

    fn optional_register(&mut self) -> Result<Option<VmRegister>> {
        let value = self.u16()?;
        Ok((value != u16::MAX).then_some(VmRegister(value)))
    }

    fn target(&mut self) -> Result<usize> {
        usize::try_from(self.u32()?)
            .map_err(|_| VmError::MalformedBytecode("jump target exceeds usize".to_owned()))
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self
            .position
            .checked_add(N)
            .ok_or_else(|| VmError::MalformedBytecode("bytecode offset overflow".to_owned()))?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| VmError::MalformedBytecode("unexpected end of stream".to_owned()))?;
        let mut result = [0_u8; N];
        result.copy_from_slice(slice);
        self.position = end;
        Ok(result)
    }
}

fn encode_operands(writer: &mut BytecodeWriter, instruction: &VmInstruction) -> Result<()> {
    match instruction {
        VmInstruction::Nop | VmInstruction::ReturnVoid => {}
        VmInstruction::LoadConst { dst, constant } => {
            writer.register(*dst);
            writer.u16(*constant);
        }
        VmInstruction::Move { dst, src } | VmInstruction::Neg { dst, src } => {
            writer.register(*dst);
            writer.register(*src);
        }
        VmInstruction::Add { dst, left, right }
        | VmInstruction::Sub { dst, left, right }
        | VmInstruction::Mul { dst, left, right }
        | VmInstruction::Div { dst, left, right }
        | VmInstruction::Rem { dst, left, right }
        | VmInstruction::And { dst, left, right }
        | VmInstruction::Or { dst, left, right }
        | VmInstruction::Xor { dst, left, right } => {
            writer.register(*dst);
            writer.register(*left);
            writer.register(*right);
        }
        VmInstruction::Jump { target } => writer.target(*target)?,
        VmInstruction::Branch {
            condition,
            left,
            right,
            target,
        } => {
            writer.u8(branch_condition_code(*condition));
            writer.register(*left);
            writer.optional_register(*right);
            writer.target(*target)?;
        }
        VmInstruction::LoadField { dst, object, field } => {
            writer.register(*dst);
            writer.optional_register(*object);
            writer.u32(*field);
        }
        VmInstruction::StoreField { object, field, src } => {
            writer.optional_register(*object);
            writer.u32(*field);
            writer.register(*src);
        }
        VmInstruction::Call { dst, method, args } => {
            writer.optional_register(*dst);
            writer.u32(*method);
            writer.u16(u16::try_from(args.len()).map_err(|_| {
                VmError::MalformedBytecode("call argument count exceeds u16".to_owned())
            })?);
            for argument in args {
                writer.register(*argument);
            }
        }
        VmInstruction::Throw { src } | VmInstruction::Return { src } => writer.register(*src),
    }
    Ok(())
}

fn decode_instruction(
    reader: &mut BytecodeReader<'_>,
    semantic: SemanticOpcode,
) -> Result<VmInstruction> {
    let instruction = match semantic {
        SemanticOpcode::Nop => VmInstruction::Nop,
        SemanticOpcode::LoadConst => VmInstruction::LoadConst {
            dst: reader.register()?,
            constant: reader.u16()?,
        },
        SemanticOpcode::Move => VmInstruction::Move {
            dst: reader.register()?,
            src: reader.register()?,
        },
        SemanticOpcode::Add => decode_binary(reader, BinaryKind::Add)?,
        SemanticOpcode::Sub => decode_binary(reader, BinaryKind::Sub)?,
        SemanticOpcode::Mul => decode_binary(reader, BinaryKind::Mul)?,
        SemanticOpcode::Div => decode_binary(reader, BinaryKind::Div)?,
        SemanticOpcode::Rem => decode_binary(reader, BinaryKind::Rem)?,
        SemanticOpcode::And => decode_binary(reader, BinaryKind::And)?,
        SemanticOpcode::Or => decode_binary(reader, BinaryKind::Or)?,
        SemanticOpcode::Xor => decode_binary(reader, BinaryKind::Xor)?,
        SemanticOpcode::Neg => VmInstruction::Neg {
            dst: reader.register()?,
            src: reader.register()?,
        },
        SemanticOpcode::Jump => VmInstruction::Jump {
            target: reader.target()?,
        },
        SemanticOpcode::Branch => VmInstruction::Branch {
            condition: decode_branch_condition(reader.u8()?)?,
            left: reader.register()?,
            right: reader.optional_register()?,
            target: reader.target()?,
        },
        SemanticOpcode::LoadField => VmInstruction::LoadField {
            dst: reader.register()?,
            object: reader.optional_register()?,
            field: reader.u32()?,
        },
        SemanticOpcode::StoreField => VmInstruction::StoreField {
            object: reader.optional_register()?,
            field: reader.u32()?,
            src: reader.register()?,
        },
        SemanticOpcode::Call => {
            let dst = reader.optional_register()?;
            let method = reader.u32()?;
            let count = usize::from(reader.u16()?);
            let mut args = Vec::with_capacity(count);
            for _ in 0..count {
                args.push(reader.register()?);
            }
            VmInstruction::Call { dst, method, args }
        }
        SemanticOpcode::Throw => VmInstruction::Throw {
            src: reader.register()?,
        },
        SemanticOpcode::Return => VmInstruction::Return {
            src: reader.register()?,
        },
        SemanticOpcode::ReturnVoid => VmInstruction::ReturnVoid,
    };
    Ok(instruction)
}

#[derive(Debug, Clone, Copy)]
enum BinaryKind {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
}

fn decode_binary(reader: &mut BytecodeReader<'_>, kind: BinaryKind) -> Result<VmInstruction> {
    let dst = reader.register()?;
    let left = reader.register()?;
    let right = reader.register()?;
    Ok(match kind {
        BinaryKind::Add => VmInstruction::Add { dst, left, right },
        BinaryKind::Sub => VmInstruction::Sub { dst, left, right },
        BinaryKind::Mul => VmInstruction::Mul { dst, left, right },
        BinaryKind::Div => VmInstruction::Div { dst, left, right },
        BinaryKind::Rem => VmInstruction::Rem { dst, left, right },
        BinaryKind::And => VmInstruction::And { dst, left, right },
        BinaryKind::Or => VmInstruction::Or { dst, left, right },
        BinaryKind::Xor => VmInstruction::Xor { dst, left, right },
    })
}

const fn branch_condition_code(condition: BranchCondition) -> u8 {
    match condition {
        BranchCondition::Eq => 0,
        BranchCondition::Ne => 1,
        BranchCondition::Lt => 2,
        BranchCondition::Ge => 3,
        BranchCondition::Gt => 4,
        BranchCondition::Le => 5,
        BranchCondition::EqZero => 6,
        BranchCondition::NeZero => 7,
        BranchCondition::LtZero => 8,
        BranchCondition::GeZero => 9,
        BranchCondition::GtZero => 10,
        BranchCondition::LeZero => 11,
    }
}

fn decode_branch_condition(value: u8) -> Result<BranchCondition> {
    match value {
        0 => Ok(BranchCondition::Eq),
        1 => Ok(BranchCondition::Ne),
        2 => Ok(BranchCondition::Lt),
        3 => Ok(BranchCondition::Ge),
        4 => Ok(BranchCondition::Gt),
        5 => Ok(BranchCondition::Le),
        6 => Ok(BranchCondition::EqZero),
        7 => Ok(BranchCondition::NeZero),
        8 => Ok(BranchCondition::LtZero),
        9 => Ok(BranchCondition::GeZero),
        10 => Ok(BranchCondition::GtZero),
        11 => Ok(BranchCondition::LeZero),
        other => Err(VmError::MalformedBytecode(format!(
            "invalid branch condition {other}"
        ))),
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
    hasher.update(
        u64::try_from(build_id.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(build_id.as_bytes());
    hasher.update(u64::try_from(seed.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(seed);
    hasher.update(u64::try_from(index).unwrap_or(u64::MAX).to_le_bytes());
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
