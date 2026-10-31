//! Shared, real O.1 APK execution with an explicit experimental acceptance boundary.
#[path = "integrated_config.rs"]
mod config;
#[path = "integrated_native.rs"]
mod native;
#[path = "integrated_verify.rs"]
mod verify;
#[path = "integrated_workspace.rs"]
mod workspace;
use crate::{
    input_snapshot::InputSnapshot, runtime_smali::refuse, ProductionBuildContext,
    ProductionControl, ProtectionRequest, Result, SmaliTools,
};
use config::{read_diversity, read_key, IntegratedConfig};
use nexora_shield_crypto::{seal_retrace_map, BuildIdentity, KeySchedule, RetraceMap};
use nexora_shield_dex::{MultiDexRewriteConfig, RenameConfig, Selection};
use nexora_shield_integrity::Sha256Digest;
use nexora_shield_package::{
    read_decoded_entry, read_zip_directory, sha256_file, verify_apk_structure,
    verify_normalized_equivalence, AndroidTools, ApkInspection,
};
use nexora_shield_rasp::PolicyMode;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use workspace::{private_write, Workspace};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegratedBuildResult {
    pub output_sha256: String,
    pub evidence_sha256: String,
    pub protected_strings: usize,
    pub protected_constants: usize,
    pub protected_resources: usize,
    pub virtualized_methods: usize,
}
/// Execute the complete eligible DEX/runtime/rebuild/sign/verify transaction.
/// # Errors
/// Rejects unavailable controls, unsafe inputs, tool failures and verification failures.
/// Global production readiness remains unchanged; no legacy fallback is used.
pub fn protect_integrated_apk(
    request: &ProtectionRequest,
    configuration: &Path,
) -> Result<IntegratedBuildResult> {
    let config = IntegratedConfig::load(configuration)?;
    let destinations = validate_request(request, &config, configuration)?;
    let overrides = config.overrides()?;
    let context =
        ProductionBuildContext::prepare_with_selection(request, &overrides, &config.dex_policy()?)?;
    validate_policy(context.policy())?;
    let _ = context.inspect_dex()?;
    let smali = SmaliTools::new(&config.tools.java, &config.tools.smali_directory)?;
    let Material {
        root,
        graph_key,
        seed,
        mode,
        retrace_key,
        certificate,
        rasp,
    } = capture_material(&config)?;
    let snapshot = InputSnapshot::capture(context.input(), context.input_sha256())?;
    let mut frozen = request.clone();
    frozen.input = snapshot.path();
    let frozen_context =
        ProductionBuildContext::prepare_with_selection(&frozen, &overrides, &config.dex_policy()?)?;
    let selections = frozen_runtime_selection(&frozen.input, &config.runtime_policy()?)?;
    let version = manifest_version(&frozen.input)?;
    let work = Workspace::create(request.output.parent().unwrap_or_else(|| Path::new(".")))?;
    let transformed = work.path.join("transformed.apk");
    let rewrite = rewrite_configuration(&config, &seed, &mode, context.input_sha256())?;
    let (dex, records) = frozen_context.stage_dex_for_engine(&transformed, &rewrite)?;
    if dex.skipped_cross_dex_rename_units != 0 || (config.dex.rename && records.is_empty()) {
        return Err(refuse("selected DEX renaming did not execute completely"));
    }
    frozen.input = transformed;
    let runtime_context = ProductionBuildContext::prepare_with_selection(
        &frozen,
        &overrides,
        &config.runtime_policy()?,
    )?;
    let identity = BuildIdentity::new(&config.application_id, &config.build_id)
        .map_err(|_| refuse("invalid integrated build identity"))?;
    let mut plan =
        runtime_context.prepare_runtime_resolved(&root, identity, &seed, mode, &selections)?;
    if !config.assets.is_empty() {
        plan = plan.with_protected_assets(&config.assets)?;
    }
    let plan = plan.bind_apk_guard(&graph_key, certificate.0, rasp)?;
    let image = work.path.join("runtime.nshield-private");
    plan.write_native_configuration(&image)?;
    let mut native = native::compile(&config.tools, plan.image(), &image, &work.path)?;
    let unsigned = work.path.join("runtime.apk");
    let runtime = plan.stage_in_transaction(&unsigned, &smali, &native.directory)?;
    verify_selected_controls(&runtime)?;
    let signed = finish_apk(
        request,
        &unsigned,
        &work.path,
        certificate,
        &mut native.versions,
    )?;
    let checks = verify::final_guard(&signed, plan.image(), certificate, version, rasp)?;
    let output = verify_apk_structure(&signed)?;
    let map_path = write_retrace(
        &config,
        &work.path,
        retrace_key.as_deref(),
        plan.image(),
        &output.sha256,
        records,
    )?;
    let input = verify_apk_structure(&snapshot.path())?;
    let evidence = build_evidence(&EvidenceInput {
        request,
        config: &config,
        input: &input,
        output: &output,
        dex: &dex,
        runtime: &runtime,
        native: &native,
        image: plan.image(),
        checks,
        retrace: map_path.as_deref(),
    })?;
    let report = work.path.join("evidence.json");
    private_write(&report, &evidence)?;
    let evidence_hash = sha256_file(&report)?;
    context.verify_input_unchanged()?;
    if validate_request(request, &config, configuration)? != destinations {
        return Err(refuse("integrated output paths changed during execution"));
    }
    let _ = SmaliTools::new(&config.tools.java, &config.tools.smali_directory)?;
    publish_outputs(request, &config, &signed, &report, map_path.as_deref())?;
    Ok(IntegratedBuildResult {
        output_sha256: output.sha256,
        evidence_sha256: evidence_hash,
        protected_strings: runtime.protected_strings,
        protected_constants: runtime.protected_constants,
        protected_resources: runtime.protected_resources,
        virtualized_methods: runtime.virtualized_methods,
    })
}
fn frozen_runtime_selection(
    source: &Path,
    policy: &crate::DexSelectorPolicy,
) -> Result<Vec<Selection>> {
    let directory = read_zip_directory(source)?;
    let set = crate::android_runtime::read_runtime_dex(source, &directory)?;
    crate::dex_preflight::resolve_effective_selection(&set, policy)
}
fn verify_selected_controls(r: &crate::RuntimeStageEvidence) -> Result<()> {
    if r.protected_strings + r.protected_constants + r.protected_resources == 0
        || r.virtualized_methods == 0
    {
        return Err(refuse(
            "selected data/VM controls produced no actual protected payloads",
        ));
    }
    Ok(())
}
fn publish_outputs(
    request: &ProtectionRequest,
    config: &IntegratedConfig,
    signed: &Path,
    report: &Path,
    map: Option<&Path>,
) -> Result<()> {
    let mut files = vec![
        (signed, request.output.as_path()),
        (
            report,
            request
                .public_report
                .as_deref()
                .ok_or_else(|| refuse("final evidence path required"))?,
        ),
    ];
    if let (Some(source), Some(target)) = (map, config.retrace_output.as_deref()) {
        files.push((source, target));
    }
    workspace::publish(&files, request.overwrite)
}
struct Material {
    root: zeroize::Zeroizing<[u8; 32]>,
    graph_key: zeroize::Zeroizing<[u8; 32]>,
    seed: nexora_shield_diversity::PrivateBuildSeed,
    mode: nexora_shield_diversity::DiversityMode,
    retrace_key: Option<zeroize::Zeroizing<[u8; 32]>>,
    certificate: Sha256Digest,
    rasp: PolicyMode,
}
fn capture_material(c: &IntegratedConfig) -> Result<Material> {
    let root = read_key(&c.root_key_file)?;
    let graph_key = read_key(&c.graph_key_file)?;
    let (seed, mode) = read_diversity(&c.diversity_file)?;
    let retrace_key = c.retrace_key_file.as_deref().map(read_key).transpose()?;
    if let Some(key) = &retrace_key {
        if key.as_ref() == root.as_ref()
            || key.as_ref() == graph_key.as_ref()
            || seed.matches_material(key.as_ref())
        {
            return Err(refuse(
                "private retrace key must be independent of client, graph and diversity keys",
            ));
        }
    }
    if root.as_ref() == graph_key.as_ref()
        || seed.matches_material(root.as_ref())
        || seed.matches_material(graph_key.as_ref())
    {
        return Err(refuse(
            "client, graph and diversity key roles must be independent",
        ));
    }
    let certificate = c
        .signer_sha256
        .parse::<Sha256Digest>()
        .map_err(|_| refuse("invalid expected APK signer SHA-256"))?;
    let rasp = match c.rasp_mode.as_str() {
        "report-only" => PolicyMode::ReportOnly,
        "enforce" => PolicyMode::Enforce,
        _ => return Err(refuse("invalid integrated RASP mode")),
    };
    Ok(Material {
        root,
        graph_key,
        seed,
        mode,
        retrace_key,
        certificate,
        rasp,
    })
}
fn rewrite_configuration(
    c: &IntegratedConfig,
    seed: &nexora_shield_diversity::PrivateBuildSeed,
    mode: &nexora_shield_diversity::DiversityMode,
    input: &str,
) -> Result<MultiDexRewriteConfig> {
    use nexora_shield_diversity::{BuildSeedContext, DiversityDomain, SeedDeriver};
    let rename = if c.dex.rename {
        let d = SeedDeriver::derive(
            seed,
            &BuildSeedContext {
                application_id: c.application_id.clone(),
                build_id: format!("{}:{input}", c.build_id),
                mode: mode.clone(),
            },
        )
        .map_err(|_| refuse("invalid integrated rename allocation"))?;
        Some(RenameConfig {
            seed: d
                .derive_u64(DiversityDomain::Rename, b"integrated-dex-rename-v1")
                .map_err(|_| refuse("integrated rename seed allocation failed"))?,
            ..RenameConfig::default()
        })
    } else {
        None
    };
    Ok(MultiDexRewriteConfig {
        rename,
        strip_metadata: c.dex.strip_metadata,
        ..MultiDexRewriteConfig::default()
    })
}
fn validate_policy(p: crate::EffectiveProductionPolicy) -> Result<()> {
    if p.enabled(ProductionControl::Attestation) {
        return Err(refuse(
            "selected attestation has no integrated Android executor; no APK created",
        ));
    }
    for c in [
        ProductionControl::DataProtection,
        ProductionControl::NativeShield,
        ProductionControl::VmShield,
        ProductionControl::Diversity,
        ProductionControl::IntegrityGraph,
        ProductionControl::RaspRuntime,
    ] {
        if !p.enabled(c) {
            return Err(refuse("experimental integrated recipe requires explicit data/native/VM/diversity/integrity/RASP selection"));
        }
    }
    Ok(())
}
fn validate_request(
    r: &ProtectionRequest,
    c: &IntegratedConfig,
    configuration: &Path,
) -> Result<Vec<PathBuf>> {
    if !r.align
        || r.allow_unsigned
        || r.signing.is_none()
        || r.public_report.is_none()
        || r.private_report.is_some()
    {
        return Err(refuse("integrated execution requires aligned signed output and public evidence; use retrace_output for the encrypted private map"));
    }
    crate::production::validate_reserved_paths(r)?;
    let mut inputs = c
        .input_paths()
        .into_iter()
        .map(PathBuf::as_path)
        .collect::<Vec<_>>();
    inputs.extend([r.input.as_path(), configuration]);
    if let Some(s) = &r.signing {
        inputs.push(&s.keystore);
    }
    let mut outputs = vec![
        r.output.as_path(),
        r.public_report
            .as_deref()
            .ok_or_else(|| refuse("public evidence required"))?,
    ];
    outputs.extend(c.retrace_output.as_deref());
    let mut identities = Vec::new();
    for (i, path) in outputs.iter().enumerate() {
        if fs::symlink_metadata(path).is_ok_and(|m| !m.is_file()) {
            return Err(refuse(
                "integrated output cannot replace a symlink or non-file",
            ));
        }
        for other in inputs.iter().chain(outputs[..i].iter()) {
            if aliases(path, other)? {
                return Err(refuse(
                    "integrated output aliases an input, key, tool or another output",
                ));
            }
        }
        let normalized = crate::production::normalized_destination(path)?;
        identities.push(normalized.clone());
        for root in [
            &c.tools.smali_directory,
            &c.tools.ndk_directory,
            &c.tools.native_cache,
            &c.tools.native_source.join("crates"),
            &c.tools.native_source.join("tools"),
        ] {
            if normalized.starts_with(crate::production::normalized_destination(root)?) {
                return Err(refuse(
                    "integrated output overlaps protected build inputs/cache",
                ));
            }
        }
    }
    Ok(identities)
}
fn aliases(a: &Path, b: &Path) -> Result<bool> {
    if crate::production::normalized_destination(a)?
        == crate::production::normalized_destination(b)?
    {
        return Ok(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(a), Ok(b)) = (fs::metadata(a), fs::metadata(b)) {
            return Ok(a.dev() == b.dev() && a.ino() == b.ino());
        }
    }
    Ok(false)
}
fn manifest_version(path: &Path) -> Result<u64> {
    let d = read_zip_directory(path)?;
    let e = d
        .entries
        .iter()
        .find(|e| e.name == "AndroidManifest.xml")
        .ok_or_else(|| refuse("missing compiled manifest"))?;
    crate::android_binary_xml::runtime_manifest_version(&read_decoded_entry(
        path,
        e,
        16 * 1024 * 1024,
    )?)
}
fn finish_apk(
    r: &ProtectionRequest,
    unsigned: &Path,
    work: &Path,
    expected: Sha256Digest,
    versions: &mut BTreeMap<String, String>,
) -> Result<PathBuf> {
    let tools = AndroidTools::discover(r.zipalign.as_deref(), r.apksigner.as_deref())?;
    let aligned = work.join("aligned.apk");
    tools
        .align(unsigned, &aligned)
        .map_err(|_| refuse("integrated alignment failed"))?;
    verify_normalized_equivalence(unsigned, &aligned)?;
    let signing = r
        .signing
        .as_ref()
        .ok_or_else(|| refuse("signing configuration required"))?;
    let signed = work.join("signed.apk");
    tools
        .sign(&aligned, &signed, signing)
        .map_err(|_| refuse("integrated APK signing failed; no output published"))?;
    let diagnostics = tools
        .verify_signature(&signed, signing.min_sdk)
        .map_err(|_| refuse("final APK signature verification failed"))?;
    if verify::signer_digest(&diagnostics)? != expected {
        return Err(refuse(
            "final APK signer differs from the certificate bound into its guard",
        ));
    }
    verify::signing_payloads(unsigned, &signed)?;
    verify::final_alignment(&tools, &signed, work)?;
    let mut command = Command::new(&tools.apksigner);
    command.arg("version");
    let version = native::run(
        &mut command,
        work,
        Duration::from_secs(30),
        "apksigner version",
    )?;
    if version.trim().is_empty() || version.trim().len() > 128 || version.trim().contains('\n') {
        return Err(refuse("invalid apksigner version response"));
    }
    versions.insert("apksigner".into(), version.trim().into());
    versions.insert(
        "zipalign_binary_sha256".into(),
        sha256_file(&tools.zipalign)?,
    );
    versions.insert(
        "apksigner_launcher_sha256".into(),
        sha256_file(&tools.apksigner)?,
    );
    Ok(signed)
}
fn write_retrace(
    c: &IntegratedConfig,
    work: &Path,
    key: Option<&[u8; 32]>,
    image: &nexora_shield_native::RuntimeImage,
    hash: &str,
    records: Vec<nexora_shield_crypto::RetraceRecord>,
) -> Result<Option<PathBuf>> {
    if !c.dex.rename {
        return Ok(None);
    }
    let key = key.ok_or_else(|| refuse("independent retrace key required"))?;
    let identity = BuildIdentity::new(&c.application_id, &image.build_id)
        .map_err(|_| refuse("invalid retrace identity"))?;
    let schedule =
        KeySchedule::new(key, identity).map_err(|_| refuse("invalid private retrace schedule"))?;
    let map = RetraceMap::new(&schedule, hash, records)
        .map_err(|_| refuse("invalid final-APK retrace records"))?;
    let cipher =
        seal_retrace_map(&schedule, &map).map_err(|_| refuse("final retrace encryption failed"))?;
    let p = work.join("retrace.nshield-map");
    private_write(&p, &cipher)?;
    Ok(Some(p))
}
struct EvidenceInput<'a> {
    request: &'a ProtectionRequest,
    config: &'a IntegratedConfig,
    input: &'a ApkInspection,
    output: &'a ApkInspection,
    dex: &'a crate::StagedDexResult,
    runtime: &'a crate::RuntimeStageEvidence,
    native: &'a native::NativeBuild,
    image: &'a nexora_shield_native::RuntimeImage,
    checks: usize,
    retrace: Option<&'a Path>,
}
fn build_evidence(e: &EvidenceInput<'_>) -> Result<Vec<u8>> {
    let p = crate::EffectiveProductionPolicy::resolve(e.request.profile, &e.config.overrides()?)?;
    let mut controls = serde_json::Map::new();
    for c in [
        ProductionControl::DataProtection,
        ProductionControl::NativeShield,
        ProductionControl::VmShield,
        ProductionControl::Diversity,
        ProductionControl::IntegrityGraph,
        ProductionControl::RaspRuntime,
        ProductionControl::Attestation,
    ] {
        controls.insert(c.as_str().into(), p.enabled(c).into());
    }
    let stages = [
        "inspect",
        "configure",
        "dex-parse",
        "compatibility",
        "selectors",
        "dex-transform",
        "data-protection",
        "native-shield",
        "vm-shield",
        "diversity",
        "integrity-graph",
        "rasp-runtime",
        "rebuild",
        "align",
        "sign",
        "final-verify",
        "evidence",
    ];
    let value = serde_json::json!({"schema_version":1,"build_id":e.config.build_id,"runtime_build_id":e.image.build_id,"application_id":e.image.application_id,"profile":e.request.profile.as_str(),
 "protection_scope":"o1-integrated-experimental","production_protected":false,"release_decision":"no-go",
 "input_sha256":e.input.sha256,"input_size":e.input.file_size,"output_sha256":e.output.sha256,"output_size":e.output.file_size,"stripped_signature_entries":e.input.legacy_signature_entries.len(),
 "entry_count":e.output.entry_count,"dex_count":e.output.dex_files.len(),"manifest_format":e.output.manifest.format.as_str(),"aligned":true,"signed":true,"signature_verified":true,"signer_sha256":e.config.signer_sha256,
 "graph_checks_verified":e.checks,"rasp_mode":e.config.rasp_mode,"host_rasp_policy_verified":true,"android_execution":"not-run","executed_controls":controls,"stages":stages,
 "dex":e.dex,"runtime":e.runtime,"native_source_sha256":e.native.source_sha256,"tool_versions":e.native.versions,"private_retrace_sha256":e.retrace.map(sha256_file).transpose()?,
 "attestation":"disabled","source_commit":option_env!("NEXORA_SOURCE_COMMIT").unwrap_or("not-recorded")});
    serde_json::to_vec_pretty(&value).map_err(|_| refuse("final evidence encoding failed"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn integrated_policy_rejects_missing_controls_and_attestation() -> Result<()> {
        for profile in [
            crate::ProtectionProfile::Standard,
            crate::ProtectionProfile::Hardened,
        ] {
            assert!(validate_policy(crate::EffectiveProductionPolicy::resolve(
                profile,
                &crate::ProductionOverrides::default()
            )?)
            .is_err());
        }
        assert!(validate_policy(crate::EffectiveProductionPolicy::resolve(
            crate::ProtectionProfile::Maximum,
            &crate::ProductionOverrides::default()
        )?)
        .is_ok());
        let mut o = crate::ProductionOverrides::default();
        o.set(ProductionControl::Attestation, true)?;
        assert!(validate_policy(crate::EffectiveProductionPolicy::resolve(
            crate::ProtectionProfile::Maximum,
            &o
        )?)
        .is_err());
        Ok(())
    }
}
