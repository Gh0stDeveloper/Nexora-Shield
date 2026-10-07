use crate::error::Result;
use crate::opcode::{OpcodeAllocation, ALL_SEMANTIC_OPCODES};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityBenchmarkReport {
    pub builds: usize,
    pub unique_opcode_maps: usize,
    pub maximum_shared_assignments: usize,
    pub maximum_transfer_basis_points: u32,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct VmSecurityBenchmark;

impl VmSecurityBenchmark {
    pub fn opcode_diversity(
        private_seed: &[u8],
        build_ids: &[String],
    ) -> Result<SecurityBenchmarkReport> {
        let allocations = build_ids
            .iter()
            .map(|build_id| OpcodeAllocation::derive(build_id, private_seed))
            .collect::<Result<Vec<_>>>()?;

        let unique_opcode_maps = allocations
            .iter()
            .map(OpcodeAllocation::fingerprint)
            .collect::<BTreeSet<_>>()
            .len();

        let mut maximum_shared_assignments = 0_usize;
        for left in 0..allocations.len() {
            for right in (left + 1)..allocations.len() {
                maximum_shared_assignments = maximum_shared_assignments
                    .max(allocations[left].same_assignments(&allocations[right]));
            }
        }

        let denominator = ALL_SEMANTIC_OPCODES.len().max(1);
        let numerator =
            u64::try_from(maximum_shared_assignments).unwrap_or(u64::MAX).saturating_mul(10_000);
        let denominator = u64::try_from(denominator).unwrap_or(u64::MAX);
        let transfer = numerator.checked_div(denominator).unwrap_or(u64::MAX);

        Ok(SecurityBenchmarkReport {
            builds: allocations.len(),
            unique_opcode_maps,
            maximum_shared_assignments,
            maximum_transfer_basis_points: u32::try_from(transfer).unwrap_or(u32::MAX),
        })
    }
}
