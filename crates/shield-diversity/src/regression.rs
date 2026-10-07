use crate::cfg::CfgVariantPlan;
use crate::integrity::IntegrityTopologyPlan;
use crate::native::NativeConstantVariant;
use crate::pass::PassVariantPlan;
use crate::rename::RenameVariant;
use crate::strings::StringPartitionPlan;
use crate::vm::VmMapVariant;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiversitySurface {
    Rename,
    PassOrder,
    Cfg,
    IntegrityTopology,
    StringPartition,
    VmMap,
    NativeConstants,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildDiversitySignature {
    pub surfaces: BTreeMap<DiversitySurface, [u8; 32]>,
    pub full_fingerprint: [u8; 32],
}

impl BuildDiversitySignature {
    #[must_use]
    pub fn from_components(
        rename: &RenameVariant,
        passes: &PassVariantPlan,
        cfg: &CfgVariantPlan,
        integrity: &IntegrityTopologyPlan,
        strings: &StringPartitionPlan,
        vm: &VmMapVariant,
        native: &NativeConstantVariant,
    ) -> Self {
        let surfaces = BTreeMap::from([
            (DiversitySurface::Rename, rename.fingerprint()),
            (DiversitySurface::PassOrder, passes.fingerprint),
            (DiversitySurface::Cfg, cfg.fingerprint),
            (DiversitySurface::IntegrityTopology, integrity.fingerprint),
            (DiversitySurface::StringPartition, strings.fingerprint),
            (DiversitySurface::VmMap, vm.fingerprint),
            (DiversitySurface::NativeConstants, native.fingerprint),
        ]);
        let full_fingerprint = full_fingerprint(&surfaces);
        Self {
            surfaces,
            full_fingerprint,
        }
    }

    #[must_use]
    pub fn shared_surfaces(&self, other: &Self) -> usize {
        self.surfaces
            .iter()
            .filter(|(surface, fingerprint)| {
                other
                    .surfaces
                    .get(surface)
                    .is_some_and(|other| other == *fingerprint)
            })
            .count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BypassPortabilityReport {
    pub builds: usize,
    pub unique_full_fingerprints: usize,
    pub compared_pairs: usize,
    pub maximum_shared_surfaces: usize,
    pub surface_count: usize,
    pub maximum_transfer_basis_points: u32,
}

impl BypassPortabilityReport {
    #[must_use]
    pub fn all_builds_unique(&self) -> bool {
        self.builds == self.unique_full_fingerprints
    }

    #[must_use]
    pub fn within_transfer_budget(&self, max_basis_points: u32) -> bool {
        self.maximum_transfer_basis_points <= max_basis_points
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CrossBuildBypassRegression;

impl CrossBuildBypassRegression {
    #[must_use]
    pub fn evaluate(signatures: &[BuildDiversitySignature]) -> BypassPortabilityReport {
        let unique_full_fingerprints = signatures
            .iter()
            .map(|signature| signature.full_fingerprint)
            .collect::<BTreeSet<_>>()
            .len();

        let surface_count = signatures
            .first()
            .map_or(0, |signature| signature.surfaces.len());
        let mut compared_pairs = 0_usize;
        let mut maximum_shared_surfaces = 0_usize;

        for left in 0..signatures.len() {
            for right in (left + 1)..signatures.len() {
                compared_pairs = compared_pairs.saturating_add(1);
                maximum_shared_surfaces = maximum_shared_surfaces
                    .max(signatures[left].shared_surfaces(&signatures[right]));
            }
        }

        let maximum_transfer_basis_points = if surface_count == 0 {
            0
        } else {
            let numerator = u64::try_from(maximum_shared_surfaces)
                .unwrap_or(u64::MAX)
                .saturating_mul(10_000);
            let denominator = u64::try_from(surface_count).unwrap_or(u64::MAX);
            u32::try_from(numerator.checked_div(denominator).unwrap_or(u64::MAX))
                .unwrap_or(u32::MAX)
        };

        BypassPortabilityReport {
            builds: signatures.len(),
            unique_full_fingerprints,
            compared_pairs,
            maximum_shared_surfaces,
            surface_count,
            maximum_transfer_basis_points,
        }
    }
}

fn full_fingerprint(surfaces: &BTreeMap<DiversitySurface, [u8; 32]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"nexora-shield/build-diversity-signature/v1");
    for (surface, fingerprint) in surfaces {
        hasher.update([surface_code(*surface)]);
        hasher.update(fingerprint);
    }
    hasher.finalize().into()
}

const fn surface_code(surface: DiversitySurface) -> u8 {
    match surface {
        DiversitySurface::Rename => 1,
        DiversitySurface::PassOrder => 2,
        DiversitySurface::Cfg => 3,
        DiversitySurface::IntegrityTopology => 4,
        DiversitySurface::StringPartition => 5,
        DiversitySurface::VmMap => 6,
        DiversitySurface::NativeConstants => 7,
    }
}
