use crate::{runtime_smali::refuse, Result};
use nexora_shield_crypto::{hex_lower, sha256, BuildIdentity};
use nexora_shield_diversity::{
    BuildSeedContext, CfgVariantPlan, DiversityDomain, DiversityMode, IntegrityTopologyPlan,
    NativeConstantVariant, PrivateBuildSeed, SeedDeriver, VmMapVariant,
};
use nexora_shield_integrity::{DistributionConfig, IntegrityManifest};
use nexora_shield_native::RuntimeImage;
use nexora_shield_vm::VmMethod;
use zeroize::{Zeroize, Zeroizing};

/// Public observations never contain private seed/mode identifiers or original symbol mappings.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RuntimeDiversityEvidence {
    pub mode: &'static str,
    pub context_commitment: String,
    pub vm_methods: usize,
    pub cfg_methods: usize,
}

pub(super) struct RuntimeDiversity {
    seed: SeedDeriver,
    private_seed: PrivateBuildSeed,
    commitment: String,
    mode: &'static str,
    methods: Vec<u32>,
    resources: Vec<u32>,
    vm_methods: usize,
    cfg_methods: usize,
}
impl RuntimeDiversity {
    pub(super) fn derive(
        private: &PrivateBuildSeed,
        identity: &BuildIdentity,
        input: &str,
        mode: DiversityMode,
    ) -> Result<Self> {
        let label = match &mode {
            DiversityMode::UniqueBuild { .. } => "unique_build",
            DiversityMode::ReproduciblePrivate { .. } => "reproducible_private",
        };
        let seed = SeedDeriver::derive(
            private,
            &BuildSeedContext {
                application_id: identity.application_id.clone(),
                build_id: format!("{}:{input}", identity.build_id),
                mode,
            },
        )
        .map_err(|_| refuse("invalid private runtime diversity configuration"))?;
        let key = Zeroizing::new(
            seed.domain_key(DiversityDomain::PassOrder)
                .map_err(|_| refuse("diversity commitment derivation failed"))?,
        );
        let commitment = hex_lower(&sha256(key.as_ref()));
        let methods = slots(&seed, 256, b"method")?;
        let resources = slots(&seed, 768, b"resource")?;
        Ok(Self {
            seed,
            private_seed: private.clone(),
            commitment,
            mode: label,
            methods,
            resources,
            vm_methods: 0,
            cfg_methods: 0,
        })
    }

    pub(super) fn matches_private_material(&self, material: &[u8]) -> bool {
        self.private_seed.matches_material(material)
    }
    pub(super) fn bind_identity(&self, identity: &mut BuildIdentity) {
        identity.build_id = format!("{}:diversity-v1-{}", identity.build_id, self.commitment);
    }
    pub(super) fn bind_native_constants(
        &self,
        root: &[u8; 32],
        image: &mut RuntimeImage,
    ) -> Result<()> {
        let (_, mut generated) = NativeConstantVariant::derive(&self.seed, &image.build_id)
            .map_err(|_| refuse("native diversity allocation failed"))?;
        let mut mask = Zeroizing::new([0u8; 32]);
        for (index, word) in generated.words.iter().enumerate() {
            mask[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        image.key_share_a.copy_from_slice(mask.as_ref());
        for (index, byte) in root.iter().enumerate() {
            image.key_share_b[index] = byte ^ mask[index];
        }
        generated.words.zeroize();
        generated.build_tag.zeroize();
        Ok(())
    }
    pub(super) fn slot(&self, ordinal: u32, resource: bool) -> Result<u32> {
        let (slots, base) = if resource {
            (&self.resources, 256)
        } else {
            (&self.methods, 0)
        };
        slots
            .get(ordinal as usize)
            .map(|slot| slot + base)
            .ok_or_else(|| refuse("diversity slot budget exceeded"))
    }
    pub(super) fn protect_vm(
        &mut self,
        slot: u32,
        key: &str,
        method: &VmMethod,
        image: &mut RuntimeImage,
    ) -> Result<()> {
        let plan = CfgVariantPlan::derive_for_vm(&self.seed, key, method)
            .map_err(|_| refuse("runtime CFG allocation failed"))?;
        let transformed = plan
            .apply(method)
            .map_err(|_| refuse("runtime CFG transformation failed"))?;
        let (_, allocation) = VmMapVariant::derive(&self.seed, &image.build_id)
            .map_err(|_| refuse("runtime VM map allocation failed"))?;
        image
            .protect_int_vm_with_allocation(slot, &transformed, allocation)
            .map_err(|_| refuse("diversified VM exceeds the integer execution contract"))?;
        self.vm_methods += 1;
        self.cfg_methods += usize::from(transformed.instructions != method.instructions);
        Ok(())
    }
    pub(super) fn integrity_manifest(
        &self,
        manifest: IntegrityManifest,
    ) -> Result<IntegrityManifest> {
        let (_, graph) = IntegrityTopologyPlan::derive(&self.seed, &manifest.graph)
            .map_err(|_| refuse("runtime integrity topology allocation failed"))?;
        let seed = Zeroizing::new(
            self.seed
                .domain_key(DiversityDomain::IntegrityTopology)
                .map_err(|_| refuse("runtime graph distribution allocation failed"))?,
        );
        let mut distribution = DistributionConfig::new(seed.to_vec(), 5, 2);
        let result = manifest.with_certificate_tree(graph, &distribution);
        distribution.seed.zeroize();
        result.map_err(|_| refuse("diversified graph lost identity/artifact/coverage invariants"))
    }
    pub(super) fn evidence(&self) -> RuntimeDiversityEvidence {
        RuntimeDiversityEvidence {
            mode: self.mode,
            context_commitment: self.commitment.clone(),
            vm_methods: self.vm_methods,
            cfg_methods: self.cfg_methods,
        }
    }
}
fn slots(seed: &SeedDeriver, count: u32, domain: &[u8]) -> Result<Vec<u32>> {
    let mut ranked = (0..count)
        .map(|slot| {
            let mut label = domain.to_vec();
            label.extend_from_slice(&slot.to_le_bytes());
            seed.derive_u64(DiversityDomain::Rename, &label)
                .map(|key| (key, slot))
                .map_err(|_| refuse("runtime slot diversification failed"))
        })
        .collect::<Result<Vec<_>>>()?;
    ranked.sort_unstable();
    Ok(ranked.into_iter().map(|(_, slot)| slot).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexora_shield_vm::{BranchCondition, ConstantPool, VmInstruction as I, VmRegister as R};
    fn branch_method() -> VmMethod {
        VmMethod {
            method_idx: 4,
            register_count: 3,
            parameter_registers: vec![R(0), R(1)],
            constants: ConstantPool::default(),
            handlers: Vec::new(),
            instructions: vec![
                I::Branch {
                    condition: BranchCondition::Lt,
                    left: R(0),
                    right: Some(R(1)),
                    target: 3,
                },
                I::Add {
                    dst: R(2),
                    left: R(0),
                    right: R(1),
                },
                I::Return { src: R(2) },
                I::Add {
                    dst: R(2),
                    left: R(1),
                    right: R(0),
                },
                I::Return { src: R(2) },
            ],
        }
    }
    #[test]
    fn runtime_diversity_is_private_repeatable_and_executes_transformed_vm() -> Result<()> {
        let private = PrivateBuildSeed::new(vec![39; 32]).map_err(|_| refuse("seed"))?;
        let identity =
            BuildIdentity::new("dev.nexora.runtime", "unit").map_err(|_| refuse("identity"))?;
        let mode = DiversityMode::ReproduciblePrivate {
            reproduction_id: "private reproduction id not shipped".into(),
        };
        let mut first = RuntimeDiversity::derive(&private, &identity, "input-sha", mode.clone())?;
        let repeat = RuntimeDiversity::derive(&private, &identity, "input-sha", mode)?;
        assert_eq!(first.evidence(), repeat.evidence());
        assert_eq!(first.methods, repeat.methods);
        assert_eq!(
            first
                .methods
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            256
        );
        let mut build = identity.clone();
        first.bind_identity(&mut build);
        assert!(!build.build_id.contains("private reproduction id"));
        let mut image = RuntimeImage::new(&[27; 32], build.clone()).map_err(|_| refuse("image"))?;
        first.bind_native_constants(&[27; 32], &mut image)?;
        assert_eq!(
            std::array::from_fn::<_, 32, _>(|i| image.key_share_a[i] ^ image.key_share_b[i]),
            [27; 32]
        );
        first.protect_vm(
            first.slot(0, false)?,
            "sum(II)I",
            &branch_method(),
            &mut image,
        )?;
        for (a, b) in [(1, 2), (5, 1), (i32::MAX, 1), (i32::MIN, -1)] {
            assert_eq!(
                image
                    .execute_int_vm(first.slot(0, false)?, &[a, b])
                    .map_err(|_| refuse("VM execute"))?,
                a.wrapping_add(b)
            );
        }
        assert_eq!(
            (first.evidence().vm_methods, first.evidence().cfg_methods),
            (1, 1)
        );
        let mut repeated = RuntimeImage::new(&[27; 32], build).map_err(|_| refuse("image"))?;
        repeat.bind_native_constants(&[27; 32], &mut repeated)?;
        let mut repeat = repeat;
        repeat.protect_vm(
            repeat.slot(0, false)?,
            "sum(II)I",
            &branch_method(),
            &mut repeated,
        )?;
        assert_eq!(
            serde_json::to_value(&image).map_err(|_| refuse("encode"))?,
            serde_json::to_value(&repeated).map_err(|_| refuse("encode"))?
        );
        Ok(())
    }
    #[test]
    fn unique_diversity_changes_actual_slots_cfg_data_and_native_masks() -> Result<()> {
        let private = PrivateBuildSeed::new(vec![40; 32]).map_err(|_| refuse("seed"))?;
        let identity =
            BuildIdentity::new("dev.nexora.runtime", "unit").map_err(|_| refuse("identity"))?;
        let mut commitments = std::collections::BTreeSet::new();
        let mut masks = std::collections::BTreeSet::new();
        let mut cfg_variants = std::collections::BTreeSet::new();
        let mut opcode_maps = std::collections::BTreeSet::new();
        for nonce in 0..32 {
            let mut plan = RuntimeDiversity::derive(
                &private,
                &identity,
                "same-input",
                DiversityMode::UniqueBuild {
                    nonce: format!("private-{nonce}"),
                },
            )?;
            assert!(commitments.insert(plan.commitment.clone()));
            let mut build = identity.clone();
            plan.bind_identity(&mut build);
            let mut image = RuntimeImage::new(&[29; 32], build).map_err(|_| refuse("image"))?;
            plan.bind_native_constants(&[29; 32], &mut image)?;
            assert!(masks.insert(image.key_share_a));
            let slot = plan.slot(0, false)?;
            plan.protect_vm(slot, "sum(II)I", &branch_method(), &mut image)?;
            assert_eq!(
                image
                    .execute_int_vm(slot, &[i32::MAX, 1])
                    .map_err(|_| refuse("VM"))?,
                i32::MIN
            );
            assert_eq!(plan.evidence().cfg_methods, 1);
            let stats = image
                .int_vm_evidence(slot)
                .map_err(|_| refuse("VM evidence"))?;
            assert!(stats.instruction_count > branch_method().instructions.len());
            cfg_variants.insert(stats.cfg_sha256);
            assert!(opcode_maps.insert(stats.opcode_map_sha256));
            assert!(plan.slot(256, false).is_err());
            assert!(plan.slot(768, true).is_err());
            assert!(plan.slot(0, true)? >= 256);
        }
        assert!(cfg_variants.len() > 1);
        Ok(())
    }
}
