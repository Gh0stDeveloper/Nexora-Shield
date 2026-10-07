use crate::error::{DiversityError, Result};
use crate::seed::{DiversityDomain, SeedDeriver};
use nexora_shield_vm::{VmInstruction, VmMethod};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CfgLayoutVariant {
    BoundaryPadding,
    BoundaryTrampoline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CfgBranchVariant {
    Preserve,
    SplitFallthrough,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfgVariantPlan {
    pub layout: CfgLayoutVariant,
    pub branch: CfgBranchVariant,
    pub selected_boundaries: Vec<usize>,
    pub padding_slots: u8,
    pub fingerprint: [u8; 32],
}

impl CfgVariantPlan {
    pub fn derive_for_vm(
        seed: &SeedDeriver,
        method_key: &str,
        method: &VmMethod,
    ) -> Result<Self> {
        method
            .validate()
            .map_err(|error| DiversityError::Cfg(error.to_string()))?;
        let boundaries = basic_block_boundaries(method);
        let mut candidates = boundaries
            .into_iter()
            .filter(|boundary| *boundary != 0 && *boundary < method.instructions.len())
            .collect::<Vec<_>>();

        let mut keyed = candidates
            .into_iter()
            .map(|boundary| {
                let label = format!("{method_key}:boundary:{boundary}");
                Ok((
                    seed.derive_u64(DiversityDomain::Cfg, label.as_bytes())?,
                    boundary,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        keyed.sort_by(|(left_key, left), (right_key, right)| {
            left_key.cmp(right_key).then_with(|| left.cmp(right))
        });
        let mut candidates = keyed
            .into_iter()
            .map(|(_, boundary)| boundary)
            .collect::<Vec<_>>();

        let selector = seed.derive_u64(DiversityDomain::Cfg, method_key.as_bytes())?;
        let layout = if selector & 1 == 0 {
            CfgLayoutVariant::BoundaryPadding
        } else {
            CfgLayoutVariant::BoundaryTrampoline
        };
        let branch = if selector & 2 == 0 {
            CfgBranchVariant::Preserve
        } else {
            CfgBranchVariant::SplitFallthrough
        };
        let padding_slots = 1 + u8::try_from((selector >> 2) % 3).unwrap_or(0);

        let max_selected = candidates.len().min(3);
        let selected_count = if max_selected == 0 {
            0
        } else {
            1 + usize::try_from(
                (selector >> 8) % u64::try_from(max_selected).unwrap_or(u64::MAX),
            )
            .unwrap_or(0)
        };
        candidates.truncate(selected_count);
        candidates.sort_unstable();

        let fingerprint = cfg_fingerprint(
            layout,
            branch,
            padding_slots,
            method_key,
            &candidates,
        );
        Ok(Self {
            layout,
            branch,
            selected_boundaries: candidates,
            padding_slots,
            fingerprint,
        })
    }

    pub fn apply(&self, method: &VmMethod) -> Result<VmMethod> {
        method
            .validate()
            .map_err(|error| DiversityError::Cfg(error.to_string()))?;

        let selected = self
            .selected_boundaries
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if selected
            .iter()
            .any(|boundary| *boundary == 0 || *boundary >= method.instructions.len())
        {
            return Err(DiversityError::Cfg(
                "selected CFG boundary is outside the VM method".to_owned(),
            ));
        }

        let old_len = method.instructions.len();
        let mut new_start = vec![0_usize; old_len + 1];
        let mut new_original = vec![0_usize; old_len];
        let mut output = Vec::<VmInstruction>::new();
        let mut trampoline_patches = Vec::<(usize, usize)>::new();

        for (old_pc, instruction) in method.instructions.iter().enumerate() {
            new_start[old_pc] = output.len();
            if selected.contains(&old_pc) {
                for _ in 0..self.padding_slots {
                    output.push(VmInstruction::Nop);
                }
                if self.layout == CfgLayoutVariant::BoundaryTrampoline {
                    let trampoline_pc = output.len();
                    output.push(VmInstruction::Jump { target: 0 });
                    trampoline_patches.push((trampoline_pc, old_pc));
                } else if self.branch == CfgBranchVariant::SplitFallthrough {
                    output.push(VmInstruction::Nop);
                }
            }
            new_original[old_pc] = output.len();
            output.push(instruction.clone());
        }
        new_start[old_len] = output.len();

        for instruction in &mut output {
            remap_instruction_targets(instruction, &new_start)?;
        }

        for (trampoline_pc, old_target) in trampoline_patches {
            output[trampoline_pc] = VmInstruction::Jump {
                target: new_original[old_target],
            };
        }

        let mut diversified = method.clone();
        diversified.instructions = output;
        for handler in &mut diversified.handlers {
            handler.start = mapped_pc(&new_start, handler.start)?;
            handler.end = mapped_pc(&new_start, handler.end)?;
            handler.target = mapped_pc(&new_start, handler.target)?;
        }

        diversified
            .validate()
            .map_err(|error| DiversityError::Cfg(error.to_string()))?;
        Ok(diversified)
    }
}

fn basic_block_boundaries(method: &VmMethod) -> BTreeSet<usize> {
    let mut boundaries = BTreeSet::from([0_usize]);
    for (pc, instruction) in method.instructions.iter().enumerate() {
        match instruction {
            VmInstruction::Jump { target } => {
                boundaries.insert(*target);
                if pc + 1 < method.instructions.len() {
                    boundaries.insert(pc + 1);
                }
            }
            VmInstruction::Branch { target, .. } => {
                boundaries.insert(*target);
                if pc + 1 < method.instructions.len() {
                    boundaries.insert(pc + 1);
                }
            }
            VmInstruction::Throw { .. }
            | VmInstruction::Return { .. }
            | VmInstruction::ReturnVoid => {
                if pc + 1 < method.instructions.len() {
                    boundaries.insert(pc + 1);
                }
            }
            _ => {}
        }
    }
    for handler in &method.handlers {
        boundaries.insert(handler.start);
        boundaries.insert(handler.end);
        boundaries.insert(handler.target);
    }
    boundaries
}

fn remap_instruction_targets(instruction: &mut VmInstruction, mapping: &[usize]) -> Result<()> {
    match instruction {
        VmInstruction::Jump { target } | VmInstruction::Branch { target, .. } => {
            *target = mapped_pc(mapping, *target)?;
        }
        _ => {}
    }
    Ok(())
}

fn mapped_pc(mapping: &[usize], old: usize) -> Result<usize> {
    mapping.get(old).copied().ok_or_else(|| {
        DiversityError::Cfg(format!("VM target pc {old} is outside the source method"))
    })
}

fn cfg_fingerprint(
    layout: CfgLayoutVariant,
    branch: CfgBranchVariant,
    padding_slots: u8,
    method_key: &str,
    boundaries: &[usize],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"nexora-shield/cfg-plan/v2");
    hasher.update([layout_code(layout), branch_code(branch), padding_slots]);
    hasher.update(
        u64::try_from(method_key.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(method_key.as_bytes());
    for boundary in boundaries {
        hasher.update(u64::try_from(*boundary).unwrap_or(u64::MAX).to_le_bytes());
    }
    hasher.finalize().into()
}

const fn layout_code(layout: CfgLayoutVariant) -> u8 {
    match layout {
        CfgLayoutVariant::BoundaryPadding => 1,
        CfgLayoutVariant::BoundaryTrampoline => 2,
    }
}

const fn branch_code(branch: CfgBranchVariant) -> u8 {
    match branch {
        CfgBranchVariant::Preserve => 1,
        CfgBranchVariant::SplitFallthrough => 2,
    }
}
