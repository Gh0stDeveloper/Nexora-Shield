use crate::ir::{VmInstruction, VmMethod};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceEstimate {
    pub instruction_count: usize,
    pub weighted_cost: u64,
    pub relative_cost_basis_points: u32,
    pub host_boundary_count: usize,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PerformanceEstimator;

impl PerformanceEstimator {
    #[must_use]
    pub fn estimate(method: &VmMethod) -> PerformanceEstimate {
        let instruction_count = method.instructions.len();
        let weighted_cost = method
            .instructions
            .iter()
            .map(instruction_cost)
            .fold(0_u64, u64::saturating_add);
        let baseline = u64::try_from(instruction_count).unwrap_or(u64::MAX).max(1);
        let ratio = weighted_cost
            .saturating_mul(10_000)
            .checked_div(baseline)
            .unwrap_or(u64::MAX);
        let relative_cost_basis_points = u32::try_from(ratio).unwrap_or(u32::MAX);
        let host_boundary_count = method
            .instructions
            .iter()
            .filter(|instruction| {
                matches!(
                    instruction,
                    VmInstruction::LoadField { .. }
                        | VmInstruction::StoreField { .. }
                        | VmInstruction::Call { .. }
                )
            })
            .count();

        PerformanceEstimate {
            instruction_count,
            weighted_cost,
            relative_cost_basis_points,
            host_boundary_count,
        }
    }
}

const fn instruction_cost(instruction: &VmInstruction) -> u64 {
    match instruction {
        VmInstruction::Nop
        | VmInstruction::LoadConst { .. }
        | VmInstruction::Move { .. }
        | VmInstruction::Add { .. }
        | VmInstruction::Sub { .. }
        | VmInstruction::And { .. }
        | VmInstruction::Or { .. }
        | VmInstruction::Xor { .. }
        | VmInstruction::Neg { .. }
        | VmInstruction::Return { .. }
        | VmInstruction::ReturnVoid => 1,
        VmInstruction::Mul { .. } | VmInstruction::Jump { .. } | VmInstruction::Branch { .. } => 2,
        VmInstruction::Div { .. } | VmInstruction::Rem { .. } => 5,
        VmInstruction::LoadField { .. } | VmInstruction::StoreField { .. } => 8,
        VmInstruction::Call { .. } => 16,
        VmInstruction::Throw { .. } => 4,
    }
}
