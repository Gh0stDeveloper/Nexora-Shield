use nexora_shield_diversity::{
    BuildDiversitySignature, BuildSeedContext, BypassPortabilityReport, CfgVariantPlan,
    CrossBuildBypassRegression, DiversityDomain, DiversityMode, IntegrityTopologyPlan,
    NativeConstantVariant, PassVariantPlan, PrivateBuildSeed, RenameVariant, SeedDeriver,
    StringPartitionPlan, VmMapVariant,
};
use nexora_shield_crypto::{ProtectedString, ProtectedStringRecord, Sensitivity};
use nexora_shield_dex::RenameConfig;
use nexora_shield_integrity::{
    IntegrityEdge, IntegrityError, IntegrityGraph, IntegrityNode, IntegrityNodeKind, Sha256Digest,
};
use nexora_shield_vm::{
    BranchCondition, ConstantPool, ExecutionConfig, Interpreter, NullHost, VmInstruction, VmMethod,
    VmRegister, VmValue,
};
use std::collections::BTreeSet;

fn private_seed(tag: u8) -> Result<PrivateBuildSeed, nexora_shield_diversity::DiversityError> {
    PrivateBuildSeed::new(vec![tag; 32])
}

fn context(build: &str, nonce: &str) -> BuildSeedContext {
    BuildSeedContext {
        application_id: "dev.nexora.sample".to_owned(),
        build_id: build.to_owned(),
        mode: DiversityMode::UniqueBuild {
            nonce: nonce.to_owned(),
        },
    }
}

fn sample_graph() -> Result<IntegrityGraph, IntegrityError> {
    let certificate = node("cert", IntegrityNodeKind::Certificate, true);
    let package = node("package", IntegrityNodeKind::Package, true);
    let dex = node("dex", IntegrityNodeKind::DexFile, true);
    let region = node("region", IntegrityNodeKind::DexRegion, true);
    let resource = node("resource", IntegrityNodeKind::Resource, false);
    let native = node("native", IntegrityNodeKind::Native, true);

    IntegrityGraph::from_parts(
        vec![
            certificate.clone(),
            package.clone(),
            dex.clone(),
            region.clone(),
            resource.clone(),
            native.clone(),
        ],
        vec![
            IntegrityEdge {
                from: certificate.id,
                to: package.id,
            },
            IntegrityEdge {
                from: package.id,
                to: dex.id,
            },
            IntegrityEdge {
                from: dex.id,
                to: region.id,
            },
            IntegrityEdge {
                from: package.id,
                to: resource.id,
            },
            IntegrityEdge {
                from: package.id,
                to: native.id,
            },
        ],
    )
}

fn sample_vm_method() -> VmMethod {
    VmMethod {
        method_idx: 41,
        register_count: 2,
        parameter_registers: vec![VmRegister(0)],
        instructions: vec![
            VmInstruction::Branch {
                condition: BranchCondition::EqZero,
                left: VmRegister(0),
                right: None,
                target: 3,
            },
            VmInstruction::Move {
                dst: VmRegister(1),
                src: VmRegister(0),
            },
            VmInstruction::Return { src: VmRegister(1) },
            VmInstruction::Neg {
                dst: VmRegister(1),
                src: VmRegister(0),
            },
            VmInstruction::Return { src: VmRegister(1) },
        ],
        constants: ConstantPool::default(),
        handlers: Vec::new(),
    }
}

fn node(label: &str, kind: IntegrityNodeKind, critical: bool) -> IntegrityNode {
    IntegrityNode {
        id: Sha256Digest::of(format!("node:{label}").as_bytes()),
        kind,
        label: label.to_owned(),
        expected: Sha256Digest::of(format!("expected:{label}").as_bytes()),
        critical,
    }
}

fn string_ids() -> Vec<String> {
    (0..12)
        .map(|index| format!("secret.logical.{index}"))
        .collect()
}

fn protected_strings(ids: &[String]) -> Vec<ProtectedString> {
    ids.iter()
        .enumerate()
        .map(|(index, logical_id)| ProtectedString {
            container: vec![u8::try_from(index).unwrap_or(0); 24],
            record: ProtectedStringRecord {
                logical_id: logical_id.clone(),
                opaque_id: format!("opaque-{index:02}"),
                sensitivity: Sensitivity::Sensitive,
                original_bytes: 8,
                protected_bytes: 24,
                reasons: vec!["phase-h-test".to_owned()],
            },
        })
        .collect()
}

fn signature(
    private: &PrivateBuildSeed,
    context: &BuildSeedContext,
) -> Result<BuildDiversitySignature, Box<dyn std::error::Error>> {
    let seed = SeedDeriver::derive(private, context)?;
    let rename = RenameVariant::derive(&seed)?;
    let passes = PassVariantPlan::derive(&seed)?;
    let vm_method = sample_vm_method();
    let cfg = CfgVariantPlan::derive_for_vm(&seed, "Ldev/nexora/Auth;->verify", &vm_method)?;
    cfg.apply(&vm_method)?.validate()?;
    let graph = sample_graph()?;
    let (integrity, diversified) = IntegrityTopologyPlan::derive(&seed, &graph)?;
    diversified.validate()?;
    let strings = StringPartitionPlan::derive(&seed, &string_ids(), 2, 5)?;
    let (vm, _) = VmMapVariant::derive(&seed, &context.build_id)?;
    let (native, _) = NativeConstantVariant::derive(&seed, &context.build_id)?;
    Ok(BuildDiversitySignature::from_components(
        &rename, &passes, &cfg, &integrity, &strings, &vm, &native,
    ))
}

#[test]
fn h1_rejects_weak_private_seed() {
    assert!(PrivateBuildSeed::new(vec![7; 31]).is_err());
}

#[test]
fn h1_domains_are_separated_and_private_material_is_redacted(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = private_seed(0x11)?;
    let seed = SeedDeriver::derive(&private, &context("build-1", "nonce-1"))?;

    let keys = [
        DiversityDomain::Rename,
        DiversityDomain::PassOrder,
        DiversityDomain::Cfg,
        DiversityDomain::IntegrityTopology,
        DiversityDomain::StringPartition,
        DiversityDomain::VmMap,
        DiversityDomain::NativeConstants,
    ]
    .into_iter()
    .map(|domain| seed.domain_key(domain))
    .collect::<Result<Vec<_>, _>>()?;

    assert_eq!(keys.iter().collect::<BTreeSet<_>>().len(), keys.len());
    assert!(format!("{private:?}").contains("REDACTED"));
    assert!(format!("{seed:?}").contains("REDACTED"));
    Ok(())
}

#[test]
fn h2_reproducible_private_mode_is_exactly_repeatable(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = private_seed(0x22)?;
    let context = BuildSeedContext {
        application_id: "dev.nexora.sample".to_owned(),
        build_id: "release-42".to_owned(),
        mode: DiversityMode::ReproduciblePrivate {
            reproduction_id: "incident-2026-10-07".to_owned(),
        },
    };

    let first = signature(&private, &context)?;
    let second = signature(&private, &context)?;
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn h2_unique_build_nonce_changes_the_plan() -> Result<(), Box<dyn std::error::Error>> {
    let private = private_seed(0x33)?;
    let first = signature(&private, &context("release-42", "nonce-a"))?;
    let second = signature(&private, &context("release-42", "nonce-b"))?;
    assert_ne!(first.full_fingerprint, second.full_fingerprint);
    Ok(())
}

#[test]
fn h3_rename_seed_changes_per_build_but_is_repeatable(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = private_seed(0x44)?;
    let first_seed = SeedDeriver::derive(&private, &context("build-a", "n-a"))?;
    let second_seed = SeedDeriver::derive(&private, &context("build-b", "n-b"))?;
    let first = RenameVariant::derive(&first_seed)?;
    let repeat = RenameVariant::derive(&first_seed)?;
    let second = RenameVariant::derive(&second_seed)?;

    let base = RenameConfig::default();
    assert_eq!(first.apply_to(&base), repeat.apply_to(&base));
    assert_ne!(first.apply_to(&base).seed, second.apply_to(&base).seed);
    assert_ne!(first.fingerprint(), second.fingerprint());
    Ok(())
}

#[test]
fn h4_pass_variants_preserve_required_constraints(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = private_seed(0x55)?;
    let mut fingerprints = BTreeSet::new();

    for index in 0..32 {
        let seed = SeedDeriver::derive(
            &private,
            &context(&format!("build-{index}"), &format!("nonce-{index}")),
        )?;
        let plan = PassVariantPlan::derive(&seed)?;
        assert!(plan.is_valid());
        fingerprints.insert(plan.fingerprint);
    }

    assert!(fingerprints.len() >= 6);
    Ok(())
}

#[test]
fn h5_cfg_variants_materialize_and_preserve_semantics(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = private_seed(0x66)?;
    let original = sample_vm_method();
    let first_seed = SeedDeriver::derive(&private, &context("cfg-a", "n-a"))?;
    let second_seed = SeedDeriver::derive(&private, &context("cfg-b", "n-b"))?;
    let first = CfgVariantPlan::derive_for_vm(&first_seed, "critical-method", &original)?;
    let second = CfgVariantPlan::derive_for_vm(&second_seed, "critical-method", &original)?;
    let first_method = first.apply(&original)?;
    let second_method = second.apply(&original)?;

    first_method.validate()?;
    second_method.validate()?;
    assert_ne!(first.fingerprint, second.fingerprint);
    assert!(first_method.instructions.len() >= original.instructions.len());
    assert!(second_method.instructions.len() >= original.instructions.len());

    for input in [-7, 0, 9] {
        let mut original_host = NullHost;
        let mut first_host = NullHost;
        let mut second_host = NullHost;
        let expected = Interpreter::execute(
            &original,
            &[VmValue::Int(input)],
            &mut original_host,
            ExecutionConfig::default(),
        )?;
        let first_result = Interpreter::execute(
            &first_method,
            &[VmValue::Int(input)],
            &mut first_host,
            ExecutionConfig::default(),
        )?;
        let second_result = Interpreter::execute(
            &second_method,
            &[VmValue::Int(input)],
            &mut second_host,
            ExecutionConfig::default(),
        )?;
        assert_eq!(first_result.value, expected.value);
        assert_eq!(second_result.value, expected.value);
    }
    Ok(())
}

#[test]
fn h6_integrity_topology_changes_without_invalidating_graph(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = private_seed(0x77)?;
    let graph = sample_graph()?;
    let mut fingerprints = BTreeSet::new();

    for index in 0..16 {
        let seed = SeedDeriver::derive(
            &private,
            &context(
                &format!("integrity-{index}"),
                &format!("integrity-nonce-{index}"),
            ),
        )?;
        let (plan, diversified) = IntegrityTopologyPlan::derive(&seed, &graph)?;
        diversified.validate()?;
        assert_eq!(diversified.nodes, graph.nodes);
        fingerprints.insert(plan.fingerprint);
    }

    assert!(fingerprints.len() > 1);
    Ok(())
}

#[test]
fn h7_string_partition_variants_cover_each_item_once(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = private_seed(0x88)?;
    let ids = string_ids();
    let first_seed = SeedDeriver::derive(&private, &context("strings-a", "n-a"))?;
    let second_seed = SeedDeriver::derive(&private, &context("strings-b", "n-b"))?;
    let first = StringPartitionPlan::derive(&first_seed, &ids, 2, 5)?;
    let second = StringPartitionPlan::derive(&second_seed, &ids, 2, 5)?;

    assert_eq!(first.total_items(), ids.len());
    assert!(first.all_shards_non_empty());
    assert_eq!(second.total_items(), ids.len());
    assert!(second.all_shards_non_empty());
    assert_ne!(first.fingerprint, second.fingerprint);

    let flattened = first
        .shards
        .iter()
        .flat_map(|shard| shard.logical_ids.iter())
        .collect::<BTreeSet<_>>();
    assert_eq!(flattened.len(), ids.len());

    let build = first.materialize(&protected_strings(&ids))?;
    assert_eq!(build.private_lookup().len(), ids.len());
    let public_json = serde_json::to_string(&build.public_shards)?;
    assert!(!public_json.contains("secret.logical."));
    assert!(!format!("{build:?}").contains("secret.logical."));
    Ok(())
}

#[test]
fn h8_vm_and_h9_native_variants_change_per_build(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = private_seed(0x99)?;
    let first_seed = SeedDeriver::derive(&private, &context("runtime-a", "n-a"))?;
    let second_seed = SeedDeriver::derive(&private, &context("runtime-b", "n-b"))?;

    let (first_vm, first_allocation) = VmMapVariant::derive(&first_seed, "runtime-a")?;
    let (second_vm, second_allocation) = VmMapVariant::derive(&second_seed, "runtime-b")?;
    assert_ne!(first_vm.fingerprint, second_vm.fingerprint);
    assert_ne!(
        first_allocation.fingerprint(),
        second_allocation.fingerprint()
    );

    let (first_native, first_data) =
        NativeConstantVariant::derive(&first_seed, "runtime-a")?;
    let (second_native, second_data) =
        NativeConstantVariant::derive(&second_seed, "runtime-b")?;
    assert_ne!(first_native.fingerprint, second_native.fingerprint);
    assert_ne!(first_data, second_data);
    Ok(())
}

#[test]
fn h10_cross_build_bypass_portability_stays_below_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = private_seed(0xaa)?;
    let signatures = (0..32)
        .map(|index| {
            signature(
                &private,
                &context(&format!("release-{index}"), &format!("nonce-{index}")),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let report: BypassPortabilityReport = CrossBuildBypassRegression::evaluate(&signatures);
    assert_eq!(report.builds, 32);
    assert!(report.all_builds_unique());
    assert_eq!(report.surface_count, 7);
    assert!(report.within_transfer_budget(3_000), "{report:?}");
    Ok(())
}
