use crate::error::Result;
use crate::seed::{DiversityDomain, SeedDeriver};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CfgLayoutVariant {
    SeededPermutation,
    SeededRotation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CfgBranchVariant {
    Preserve,
    InvertEligible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfgVariantPlan {
    pub layout: CfgLayoutVariant,
    pub branch: CfgBranchVariant,
    pub block_order: Vec<usize>,
    pub split_budget: u8,
    pub fingerprint: [u8; 32],
}

impl CfgVariantPlan {
    pub fn derive(seed: &SeedDeriver, method_key: &str, block_count: usize) -> Result<Self> {
        let selector = seed.derive_u64(DiversityDomain::Cfg, method_key.as_bytes())?;
        let layout = if selector & 1 == 0 {
            CfgLayoutVariant::SeededPermutation
        } else {
            CfgLayoutVariant::SeededRotation
        };
        let branch = if selector & 2 == 0 {
            CfgBranchVariant::Preserve
        } else {
            CfgBranchVariant::InvertEligible
        };
        let split_budget = u8::try_from((selector >> 2) % 4).unwrap_or(0);

        let mut block_order = (0..block_count).collect::<Vec<_>>();
        if block_order.len() > 2 {
            match layout {
                CfgLayoutVariant::SeededPermutation => {
                    for index in (2..block_order.len()).rev() {
                        let item = format!("{method_key}:{index}");
                        let value = seed.derive_u64(DiversityDomain::Cfg, item.as_bytes())?;
                        let span = index;
                        let swap_with = 1
                            + usize::try_from(
                                value % u64::try_from(span).unwrap_or(u64::MAX),
                            )
                            .unwrap_or(0);
                        block_order.swap(index, swap_with);
                    }
                }
                CfgLayoutVariant::SeededRotation => {
                    let tail_len = block_order.len() - 1;
                    let rotation = usize::try_from(
                        selector % u64::try_from(tail_len).unwrap_or(u64::MAX),
                    )
                    .unwrap_or(0);
                    block_order[1..].rotate_left(rotation);
                }
            }
        }

        let fingerprint =
            cfg_fingerprint(layout, branch, split_budget, method_key, &block_order);
        Ok(Self {
            layout,
            branch,
            block_order,
            split_budget,
            fingerprint,
        })
    }

    #[must_use]
    pub fn preserves_entry_block(&self) -> bool {
        self.block_order.first().copied().unwrap_or(0) == 0
    }

    #[must_use]
    pub fn is_permutation(&self) -> bool {
        let mut sorted = self.block_order.clone();
        sorted.sort_unstable();
        sorted == (0..self.block_order.len()).collect::<Vec<_>>()
    }
}

fn cfg_fingerprint(
    layout: CfgLayoutVariant,
    branch: CfgBranchVariant,
    split_budget: u8,
    method_key: &str,
    order: &[usize],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"nexora-shield/cfg-plan/v1");
    hasher.update([layout_code(layout), branch_code(branch), split_budget]);
    hasher.update(
        u64::try_from(method_key.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(method_key.as_bytes());
    for block in order {
        hasher.update(u64::try_from(*block).unwrap_or(u64::MAX).to_le_bytes());
    }
    hasher.finalize().into()
}

const fn layout_code(layout: CfgLayoutVariant) -> u8 {
    match layout {
        CfgLayoutVariant::SeededPermutation => 1,
        CfgLayoutVariant::SeededRotation => 2,
    }
}

const fn branch_code(branch: CfgBranchVariant) -> u8 {
    match branch {
        CfgBranchVariant::Preserve => 1,
        CfgBranchVariant::InvertEligible => 2,
    }
}
