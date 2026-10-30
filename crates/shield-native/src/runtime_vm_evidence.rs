//! Public digests/counts of authenticated executable VM payloads, never their plaintext.
use super::{
    validate_int_method, IntProgram, Result, RuntimeEntryKind, RuntimeError, RuntimeImage,
};
use nexora_shield_crypto::{hex_lower, sha256};
use nexora_shield_vm::{VmMethod, ALL_SEMANTIC_OPCODES};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeVmEvidence {
    pub instruction_count: usize,
    pub opcode_map_sha256: String,
    pub opcode_stream_sha256: String,
    pub cfg_sha256: String,
}
impl RuntimeImage {
    pub fn int_vm_evidence(&self, slot: u32) -> Result<RuntimeVmEvidence> {
        let bytes = self.decrypt(slot, RuntimeEntryKind::IntVm)?;
        let program: IntProgram = serde_json::from_slice(bytes.as_slice())
            .map_err(|_| RuntimeError("invalid VM evidence program"))?;
        if program.allocation.build_id() != self.build_id {
            return Err(RuntimeError("VM evidence belongs to another build"));
        }
        let mut assignments = Vec::new();
        for semantic in ALL_SEMANTIC_OPCODES {
            let opcode = program
                .allocation
                .encode(semantic)
                .map_err(|_| RuntimeError("incomplete VM opcode map"))?;
            if opcode == 0
                || program
                    .allocation
                    .decode(opcode)
                    .map_err(|_| RuntimeError("invalid VM opcode map"))?
                    != semantic
            {
                return Err(RuntimeError("non-bijective VM opcode map"));
            }
            assignments.push(opcode);
        }
        if assignments.iter().collect::<BTreeSet<_>>().len() != assignments.len() {
            return Err(RuntimeError("aliased VM opcode map"));
        }
        let instructions = program
            .stream
            .decode(&program.allocation)
            .map_err(|_| RuntimeError("invalid VM evidence bytecode"))?;
        let cfg = Zeroizing::new(
            serde_json::to_vec(&instructions)
                .map_err(|_| RuntimeError("VM evidence encoding failed"))?,
        );
        let method = VmMethod {
            method_idx: program.method_idx,
            register_count: program.register_count,
            parameter_registers: program.parameters,
            constants: program.constants,
            handlers: Vec::new(),
            instructions,
        };
        validate_int_method(&method)?;
        Ok(RuntimeVmEvidence {
            instruction_count: method.instructions.len(),
            opcode_map_sha256: hex_lower(&sha256(&assignments)),
            opcode_stream_sha256: hex_lower(&program.stream.digest()),
            cfg_sha256: hex_lower(&sha256(&cfg)),
        })
    }
}
