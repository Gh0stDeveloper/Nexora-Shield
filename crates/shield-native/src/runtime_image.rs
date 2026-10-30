//! Build-bound encrypted data and executable VM programs consumed by JNI.
//! This is a narrow static-int/string runtime, not a general Java object host.

use nexora_shield_crypto::{
    hex_lower, open, seal, sha256, BuildIdentity, ContainerKind, KeyDomain, KeySchedule,
    SensitiveBytes,
};
use nexora_shield_vm::{
    ConstantPool, ExecutionConfig, Interpreter, NullHost, OpcodeAllocation, OpcodeStream,
    VmConstant, VmInstruction, VmMethod, VmRegister, VmValue,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

const MAX_ENTRY_BYTES: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 1024;
const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeEntryKind {
    String,
    IntVm,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEntry {
    pub slot: u32,
    pub kind: RuntimeEntryKind,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeImage {
    pub schema: u32,
    pub application_id: String,
    pub build_id: String,
    pub key_share_a: [u8; 32],
    pub key_share_b: [u8; 32],
    pub entries: Vec<RuntimeEntry>,
}

impl fmt::Debug for RuntimeImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeImage")
            .field("entries", &self.entries.len())
            .field("key_material", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
impl Drop for RuntimeImage {
    fn drop(&mut self) {
        self.key_share_a.zeroize();
        self.key_share_b.zeroize();
    }
}

impl fmt::Debug for RuntimeEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeEntry")
            .field("slot", &self.slot)
            .field("kind", &self.kind)
            .field("bytes", &self.ciphertext.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeError(pub &'static str);
impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for RuntimeError {}
type Result<T> = std::result::Result<T, RuntimeError>;

#[derive(Serialize, Deserialize)]
struct IntProgram {
    method_idx: u32,
    register_count: u16,
    parameters: Vec<VmRegister>,
    constants: ConstantPool,
    allocation: OpcodeAllocation,
    stream: OpcodeStream,
}

impl RuntimeImage {
    pub fn new(root: &[u8; 32], identity: BuildIdentity) -> Result<Self> {
        let schedule = KeySchedule::new(root, identity.clone())
            .map_err(|_| RuntimeError("invalid runtime identity"))?;
        let key_share_a = schedule
            .opaque_item_id(KeyDomain::Generic, "runtime/key-share/v1")
            .map_err(|_| RuntimeError("runtime key derivation failed"))?;
        let mut key_share_b = [0; 32];
        for (i, value) in root.iter().enumerate() {
            key_share_b[i] = value ^ key_share_a[i];
        }
        Ok(Self {
            schema: 1,
            application_id: identity.application_id,
            build_id: identity.build_id,
            key_share_a,
            key_share_b,
            entries: Vec::new(),
        })
    }

    fn schedule(&self) -> Result<KeySchedule> {
        let mut root = Zeroizing::new([0u8; 32]);
        // Do not allow compile-time folding to place the reconstructed root in rodata.
        let left = std::hint::black_box(&self.key_share_a);
        let right = std::hint::black_box(&self.key_share_b);
        for i in 0..32 {
            root[i] = left[i] ^ right[i];
        }
        let identity = BuildIdentity::new(&self.application_id, &self.build_id)
            .map_err(|_| RuntimeError("invalid runtime identity"))?;
        KeySchedule::new(root.as_ref(), identity)
            .map_err(|_| RuntimeError("runtime key derivation failed"))
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 || self.entries.is_empty() || self.entries.len() > MAX_ENTRIES {
            return Err(RuntimeError("invalid runtime image schema or inventory"));
        }
        let _ = self.schedule()?;
        let mut slots = std::collections::BTreeSet::new();
        let mut total = 0usize;
        for entry in &self.entries {
            if !slots.insert(entry.slot) || entry.ciphertext.len() > MAX_ENTRY_BYTES {
                return Err(RuntimeError("invalid runtime entry or duplicate slot"));
            }
            total = total
                .checked_add(entry.ciphertext.len())
                .ok_or(RuntimeError("runtime image too large"))?;
        }
        if total > MAX_IMAGE_BYTES {
            return Err(RuntimeError("runtime image too large"));
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        let canonical = serde_json::to_value((
            self.schema,
            &self.application_id,
            &self.build_id,
            &self.entries,
        ))
        .map_err(|_| RuntimeError("runtime encoding failed"))?;
        let mut encoded = Zeroizing::new(
            serde_json::to_vec(&canonical).map_err(|_| RuntimeError("runtime encoding failed"))?,
        );
        let fingerprint = hex_lower(&sha256(&encoded));
        encoded.clear();
        Ok(fingerprint)
    }

    pub fn protect_string(&mut self, slot: u32, value: &str) -> Result<()> {
        self.insert(slot, RuntimeEntryKind::String, value.as_bytes())
    }

    pub fn protect_int_vm(&mut self, slot: u32, method: &VmMethod) -> Result<()> {
        validate_int_method(method)?;
        let schedule = self.schedule()?;
        let seed = schedule
            .opaque_item_id(KeyDomain::Generic, &format!("vm/opcodes/{slot}"))
            .map_err(|_| RuntimeError("VM opcode derivation failed"))?;
        let allocation = OpcodeAllocation::derive(&self.build_id, &seed)
            .map_err(|_| RuntimeError("VM opcode allocation failed"))?;
        let stream = OpcodeStream::encode(&method.instructions, &allocation)
            .map_err(|_| RuntimeError("VM encoding failed"))?;
        let program = IntProgram {
            method_idx: method.method_idx,
            register_count: method.register_count,
            parameters: method.parameter_registers.clone(),
            constants: method.constants.clone(),
            allocation,
            stream,
        };
        let encoded = Zeroizing::new(
            serde_json::to_vec(&program).map_err(|_| RuntimeError("VM encoding failed"))?,
        );
        self.insert(slot, RuntimeEntryKind::IntVm, &encoded)
    }

    fn insert(&mut self, slot: u32, kind: RuntimeEntryKind, plaintext: &[u8]) -> Result<()> {
        if plaintext.len() > MAX_ENTRY_BYTES / 2
            || self.entries.iter().any(|entry| entry.slot == slot)
        {
            return Err(RuntimeError("runtime entry too large or duplicate slot"));
        }
        let container = container_kind(kind);
        let ciphertext = seal(
            &self.schedule()?,
            container,
            &logical_id(kind, slot),
            plaintext,
        )
        .map_err(|_| RuntimeError("runtime encryption failed"))?;
        self.entries.push(RuntimeEntry {
            slot,
            kind,
            ciphertext,
        });
        if let Err(error) = self.validate() {
            self.entries.pop();
            return Err(error);
        }
        Ok(())
    }

    fn decrypt(&self, slot: u32, kind: RuntimeEntryKind) -> Result<SensitiveBytes> {
        self.validate()?;
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.slot == slot && entry.kind == kind)
            .ok_or(RuntimeError("runtime slot or type unavailable"))?;
        open(
            &self.schedule()?,
            container_kind(kind),
            &logical_id(kind, slot),
            &entry.ciphertext,
        )
        .map(SensitiveBytes::new)
        .map_err(|_| RuntimeError("runtime authentication failed"))
    }

    pub fn decrypt_string(&self, slot: u32) -> Result<Zeroizing<String>> {
        let plaintext = self.decrypt(slot, RuntimeEntryKind::String)?;
        let value = std::str::from_utf8(plaintext.as_slice())
            .map_err(|_| RuntimeError("invalid runtime string"))?;
        Ok(Zeroizing::new(value.to_owned()))
    }

    pub fn authenticate(&self) -> Result<()> {
        self.validate()?;
        for entry in &self.entries {
            let _ = self.decrypt(entry.slot, entry.kind)?;
        }
        Ok(())
    }

    pub fn execute_int_vm(&self, slot: u32, arguments: &[i32]) -> Result<i32> {
        if arguments.len() > 16 {
            return Err(RuntimeError("VM argument limit exceeded"));
        }
        let bytes = self.decrypt(slot, RuntimeEntryKind::IntVm)?;
        let program: IntProgram = serde_json::from_slice(bytes.as_slice())
            .map_err(|_| RuntimeError("invalid VM program"))?;
        let instructions = program
            .stream
            .decode(&program.allocation)
            .map_err(|_| RuntimeError("invalid VM bytecode"))?;
        let method = VmMethod {
            method_idx: program.method_idx,
            register_count: program.register_count,
            parameter_registers: program.parameters,
            constants: program.constants,
            handlers: Vec::new(),
            instructions,
        };
        validate_int_method(&method)?;
        let args = arguments
            .iter()
            .copied()
            .map(VmValue::Int)
            .collect::<Vec<_>>();
        let result = Interpreter::execute(
            &method,
            &args,
            &mut NullHost,
            ExecutionConfig { step_limit: 4097 },
        )
        .map_err(|_| RuntimeError("VM execution rejected"))?;
        match result.value {
            VmValue::Int(value) => Ok(value),
            _ => Err(RuntimeError("VM result is not an integer")),
        }
    }
}

fn container_kind(kind: RuntimeEntryKind) -> ContainerKind {
    match kind {
        RuntimeEntryKind::String => ContainerKind::String,
        RuntimeEntryKind::IntVm => ContainerKind::Generic,
    }
}
fn logical_id(kind: RuntimeEntryKind, slot: u32) -> String {
    format!("runtime/{kind:?}/{slot}")
}

fn validate_int_method(method: &VmMethod) -> Result<()> {
    if method.register_count > 128
        || method.parameter_registers.len() > 16
        || method.instructions.is_empty()
        || method.instructions.len() > 4096
        || !method.handlers.is_empty()
    {
        return Err(RuntimeError(
            "VM method outside supported integer runtime contract",
        ));
    }
    method
        .validate()
        .map_err(|_| RuntimeError("invalid VM method"))?;
    for (pc, instruction) in method.instructions.iter().enumerate() {
        match instruction {
            VmInstruction::Nop
            | VmInstruction::Move { .. }
            | VmInstruction::Add { .. }
            | VmInstruction::Sub { .. }
            | VmInstruction::Mul { .. }
            | VmInstruction::And { .. }
            | VmInstruction::Or { .. }
            | VmInstruction::Xor { .. }
            | VmInstruction::Neg { .. }
            | VmInstruction::Return { .. } => {}
            VmInstruction::LoadConst { constant, .. }
                if matches!(method.constants.get(*constant), Ok(VmConstant::Int(_))) => {}
            VmInstruction::Jump { target } | VmInstruction::Branch { target, .. }
                if *target > pc => {}
            _ => return Err(RuntimeError("unsupported or cyclic integer VM operation")),
        }
    }
    Ok(())
}
