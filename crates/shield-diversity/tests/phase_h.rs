use nexora_shield_diversity::{
    BuildDiversitySignature, BuildSeedContext, BypassPortabilityReport, CfgVariantPlan,
    CrossBuildBypassRegression, DiversityDomain, DiversityMode, IntegrityTopologyPlan,
    NativeConstantVariant, PassVariantPlan, PrivateBuildSeed, RenameVariant, SeedDeriver,
    StringPartitionPlan, VmMapVariant,
};
use nexora_shield_dex::RenameConfig;
use nexora_shield_integrity::{
    IntegrityEdge, IntegrityGraph, IntegrityNode, IntegrityNodeKind, Sha256Digest,
};
use std::collections::BTreeSet;

fn context(build: &str, nonce: &str) -> BuildSeedContext {
    BuildSeedContext {
        application_id: "dev.nexora.sample".to_owned(),
        build_id: build.to_owned(),
        mode: DiversityMode::UniqueBuild {
            nonce: nonce.to_owned(),
        },
    }
}

fn sample_graph() -> IntegrityGraph {
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
    .expect("sample graph must be valid")
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
    (0..12).map(|index| format!("secret.logical.{index}")).collect()
}

fn signature(
    private: &PrivateBuildSeed,
    context: &BuildSeedContext,
) -> Result<BuildDiversitySignature, Box<dyn std::error::Error>> {
    let seed = SeedDeriver::derive(private, context)?;
    let rename = RenameVariant::derive(&seed)?;
    let passes = PassVariantPlan::derive(&seed)?;
    let cfg = CfgVariantPlan::derive(&seed, "Ldev/nexora/Auth;->verify", 8)?;
    let (integrity, diversified) = IntegrityTopologyPlan::derive(&seed, &sample_graph())?;
    diversified.validate()?;
    let strings = StringPartitionPlan::derive(&seed, &string_ids(), 2, 5)?;
    let (vm, _) = VmMapVariant::derive(&seed, &context.build_id)?;
    let (native, _) = NativeConstantVariant::derive(&seed, &context.build_id)?;
    Ok(BuildDiversitySignature::from_components(
        &rename, &passes, &cfg, &integrity, &strings, &vm, &native,
    ))
}

#[test]
fn h1_domains_are_separated_and_private_material_is_redacted(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = PrivateBuildSeed::new(b"phase-h-private-seed".to_vec())?;
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
    assert!(!format!("{private:?}").contains("phase-h-private-seed"));
    assert!(format!("{private:?}").contains("REDACTED"));
    assert!(format!("{seed:?}").contains("REDACTED"));
    Ok(())
}

#[test]
fn h2_reproducible_private_mode_is_exactly_repeatable(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = PrivateBuildSeed::new(b"repro-secret".to_vec())?;
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
    let private = PrivateBuildSeed::new(b"normal-build-secret".to_vec())?;
    let first = signature(&private, &context("release-42", "nonce-a"))?;
    let second = signature(&private, &context("release-42", "nonce-b"))?;
    assert_ne!(first.full_fingerprint, second.full_fingerprint);
    Ok(())
}

#[test]
fn h3_rename_seed_changes_per_build_but_is_repeatable(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = PrivateBuildSeed::new(b"rename-secret".to_vec())?;
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
    let private = PrivateBuildSeed::new(b"pass-secret".to_vec())?;
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
fn h5_cfg_variants_preserve_entry_and_form_a_permutation(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = PrivateBuildSeed::new(b"cfg-secret".to_vec())?;
    let first_seed = SeedDeriver::derive(&private, &context("cfg-a", "n-a"))?;
    let second_seed = SeedDeriver::derive(&private, &context("cfg-b", "n-b"))?;
    let first = CfgVariantPlan::derive(&first_seed, "critical-method", 12)?;
    let second = CfgVariantPlan::derive(&second_seed, "critical-method", 12)?;

    assert!(first.preserves_entry_block());
    assert!(first.is_permutation());
    assert!(second.preserves_entry_block());
    assert!(second.is_permutation());
    assert_ne!(first.fingerprint, second.fingerprint);
    Ok(())
}

#[test]
fn h6_integrity_topology_changes_without_invalidating_graph(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = PrivateBuildSeed::new(b"integrity-secret".to_vec())?;
    let graph = sample_graph();
    let first_seed = SeedDeriver::derive(&private, &context("integrity-a", "n-a"))?;
    let second_seed = SeedDeriver::derive(&private, &context("integrity-b", "n-b"))?;
    let (first, first_graph) = IntegrityTopologyPlan::derive(&first_seed, &graph)?;
    let (second, second_graph) = IntegrityTopologyPlan::derive(&second_seed, &graph)?;

    first_graph.validate()?;
    second_graph.validate()?;
    assert_eq!(first_graph.nodes, graph.nodes);
    assert_eq!(second_graph.nodes, graph.nodes);
    assert_ne!(first.fingerprint, second.fingerprint);
    Ok(())
}

#[test]
fn h7_string_partition_variants_cover_each_item_once(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = PrivateBuildSeed::new(b"string-secret".to_vec())?;
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
    Ok(())
}

#[test]
fn h8_vm_and_h9_native_variants_change_per_build(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = PrivateBuildSeed::new(b"runtime-secret".to_vec())?;
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
    let private = PrivateBuildSeed::new(b"cross-build-regression-secret".to_vec())?;
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
