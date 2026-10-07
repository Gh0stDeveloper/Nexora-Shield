use crate::error::Result;
use crate::seed::{DiversityDomain, SeedDeriver};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiversificationPass {
    Rename,
    MetadataReduction,
    StringProtection,
    VmShield,
    NativeBinding,
    IntegrityManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassVariantPlan {
    pub ordered: Vec<DiversificationPass>,
    pub fingerprint: [u8; 32],
}

impl PassVariantPlan {
    pub fn derive(seed: &SeedDeriver) -> Result<Self> {
        let mut early = vec![
            DiversificationPass::Rename,
            DiversificationPass::MetadataReduction,
        ];
        let mut middle = vec![
            DiversificationPass::StringProtection,
            DiversificationPass::VmShield,
            DiversificationPass::NativeBinding,
        ];

        shuffle(seed, b"early", &mut early)?;
        shuffle(seed, b"middle", &mut middle)?;

        let mut ordered = early;
        ordered.extend(middle);
        ordered.push(DiversificationPass::IntegrityManifest);

        let fingerprint = fingerprint(&ordered);
        Ok(Self {
            ordered,
            fingerprint,
        })
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.ordered.len() == 6
            && self.ordered.last() == Some(&DiversificationPass::IntegrityManifest)
            && all_unique(&self.ordered)
    }
}

fn shuffle(
    seed: &SeedDeriver,
    label: &[u8],
    values: &mut [DiversificationPass],
) -> Result<()> {
    for index in (1..values.len()).rev() {
        let mut item_label = label.to_vec();
        item_label.extend_from_slice(&u64::try_from(index).unwrap_or(u64::MAX).to_le_bytes());
        let selector = seed.derive_u64(DiversityDomain::PassOrder, &item_label)?;
        let swap_with =
            usize::try_from(selector % u64::try_from(index + 1).unwrap_or(u64::MAX)).unwrap_or(0);
        values.swap(index, swap_with);
    }
    Ok(())
}

fn fingerprint(values: &[DiversificationPass]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"nexora-shield/pass-plan/v1");
    for value in values {
        hasher.update([pass_code(*value)]);
    }
    hasher.finalize().into()
}

fn all_unique(values: &[DiversificationPass]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(index, value)| !values[..index].contains(value))
}

const fn pass_code(pass: DiversificationPass) -> u8 {
    match pass {
        DiversificationPass::Rename => 1,
        DiversificationPass::MetadataReduction => 2,
        DiversificationPass::StringProtection => 3,
        DiversificationPass::VmShield => 4,
        DiversificationPass::NativeBinding => 5,
        DiversificationPass::IntegrityManifest => 6,
    }
}
