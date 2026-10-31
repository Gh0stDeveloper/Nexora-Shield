//! Internal functional Android runtime qualification, not the production protect command.
use nexora_shield_core::{
    DexSelectorPolicy, ProductionBuildContext, ProductionOverrides, ProtectionProfile,
    ProtectionRequest, SmaliTools,
};
use nexora_shield_crypto::BuildIdentity;
use nexora_shield_dex::{Selector, SelectorKind};
use std::{fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() < 7 {
        return Err("usage: stage_android_runtime <prepare|stage> <input.apk> <config-or-output> <private-root-file> <application-id> <build-id> <class#method>... [--tools <smali-dir> --java <java-path> --native <jniLibs-dir>]".into());
    }
    let input = PathBuf::from(&args[1]);
    let target = PathBuf::from(&args[2]);
    let key_path = PathBuf::from(&args[3]);
    let root = read_root(&key_path)?;
    let mut selection = DexSelectorPolicy::default();
    let mut index = 6;
    while index < args.len() && !args[index].starts_with("--") {
        let (class, method) = args[index]
            .split_once('#')
            .ok_or("invalid method selector")?;
        selection.add_include(Selector::new(
            SelectorKind::Method,
            class,
            Some(method.into()),
        )?)?;
        index += 1;
    }
    let context = ProductionBuildContext::prepare_with_selection(
        &ProtectionRequest {
            input,
            output: target.with_extension("not-production-output"),
            profile: ProtectionProfile::Standard,
            align: false,
            allow_unsigned: true,
            overwrite: false,
            signing: None,
            zipalign: None,
            apksigner: None,
            public_report: None,
            private_report: None,
        },
        &ProductionOverrides::default(),
        &selection,
    )?;
    let identity = BuildIdentity::new(&args[4], &args[5])?;
    let plan = if args.get(index).map(String::as_str) == Some("--diversity-file") {
        let path = PathBuf::from(
            args.get(index + 1)
                .ok_or("private diversity file required")?,
        );
        let (seed, mode) = read_diversity(&path)?;
        index += 2;
        context.prepare_android_runtime_with_diversity(&root, identity, &seed, mode)
    } else {
        context.prepare_android_runtime(&root, identity)
    };
    drop(root);
    let mut plan = plan?;
    let mut assets = Vec::new();
    while args.get(index).map(String::as_str) == Some("--asset") {
        assets.push(args.get(index + 1).ok_or("asset path required")?.clone());
        index += 2;
    }
    if !assets.is_empty() {
        plan = plan.with_protected_assets(&assets)?;
    }
    let (plan, index) = bind_guard(plan, &args, index)?;
    if let Some(info) = plan.diversity_evidence() {
        println!("Diversity mode: {}", info.mode);
        println!("Diversity commitment: {}", info.context_commitment);
        println!(
            "Diversified VM/CFG methods: {}/{}",
            info.vm_methods, info.cfg_methods
        );
    }
    if args[0] == "prepare" {
        if index != args.len() {
            return Err("prepare does not accept execution options".into());
        }
        plan.write_native_configuration(&target)?;
        println!("Private runtime configuration prepared; no production APK created");
    } else if args[0] == "stage" {
        let extra = &args[index..];
        if extra.len() != 6
            || extra[0] != "--tools"
            || extra[2] != "--java"
            || extra[4] != "--native"
        {
            return Err("stage requires --tools --java --native in that order".into());
        }
        let tools = SmaliTools::new(
            PathBuf::from(&extra[3]).as_path(),
            PathBuf::from(&extra[1]).as_path(),
        )?;
        let evidence = plan.stage(&target, &tools, PathBuf::from(&extra[5]).as_path())?;
        print_stage(&evidence);
    } else {
        return Err("unknown operation".into());
    }
    Ok(())
}

fn bind_guard(
    mut plan: nexora_shield_core::AndroidRuntimePlan,
    args: &[String],
    mut index: usize,
) -> Result<(nexora_shield_core::AndroidRuntimePlan, usize), Box<dyn std::error::Error>> {
    if args.get(index).map(String::as_str) == Some("--guard-key") {
        if args.get(index + 2).map(String::as_str) != Some("--signer-sha")
            || args.get(index + 4).map(String::as_str) != Some("--rasp")
            || args.len() < index + 6
        {
            return Err("guard requires --guard-key <private-file> --signer-sha <digest-file> --rasp <enforce|report-only>".into());
        }
        let key_path = PathBuf::from(&args[index + 1]);
        let metadata = fs::symlink_metadata(&key_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("APK guard signing key must be private".into());
            }
        }
        if !metadata.is_file() || metadata.len() != 32 {
            return Err("APK guard signing key must be a regular 32-byte file".into());
        }
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        std::io::Read::read_exact(&mut fs::File::open(key_path)?, key.as_mut())?;
        let certificate = fs::read_to_string(&args[index + 3])?
            .parse::<nexora_shield_integrity::Sha256Digest>()?;
        let mode = match args[index + 5].as_str() {
            "enforce" => nexora_shield_rasp::PolicyMode::Enforce,
            "report-only" => nexora_shield_rasp::PolicyMode::ReportOnly,
            _ => return Err("invalid RASP mode".into()),
        };
        plan = plan.bind_apk_guard(&key, certificate.0, mode)?;
        index += 6;
    }
    Ok((plan, index))
}

fn read_diversity(
    path: &std::path::Path,
) -> Result<
    (
        nexora_shield_diversity::PrivateBuildSeed,
        nexora_shield_diversity::DiversityMode,
    ),
    Box<dyn std::error::Error>,
> {
    use nexora_shield_diversity::{DiversityMode, PrivateBuildSeed};
    if path.extension().and_then(|p| p.to_str()) != Some("nshield-private") {
        return Err("diversity input requires the ignored .nshield-private suffix".into());
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || !(40..=295).contains(&metadata.len()) {
        return Err("invalid private diversity file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("diversity file must be private".into());
        }
    }
    let bytes = zeroize::Zeroizing::new(fs::read(path)?);
    if u64::try_from(bytes.len())? != metadata.len() || &bytes[..6] != b"NSDV1\0" {
        return Err("invalid private diversity format".into());
    }
    let value = std::str::from_utf8(&bytes[39..])?;
    if value.trim().is_empty() || value.contains('\0') {
        return Err("invalid diversity mode identifier".into());
    }
    let mode = match bytes[6] {
        0 => DiversityMode::UniqueBuild {
            nonce: value.into(),
        },
        1 => DiversityMode::ReproduciblePrivate {
            reproduction_id: value.into(),
        },
        _ => return Err("unsupported diversity mode".into()),
    };
    Ok((PrivateBuildSeed::new(bytes[7..39].to_vec())?, mode))
}

fn read_root(
    path: &std::path::Path,
) -> Result<zeroize::Zeroizing<[u8; 32]>, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("runtime root file must be private".into());
        }
    }
    if !metadata.file_type().is_file() || metadata.len() != 32 {
        return Err("runtime root must be a regular 32-byte file".into());
    }
    let mut root = zeroize::Zeroizing::new([0; 32]);
    let mut file = std::fs::File::open(path)?;
    std::io::Read::read_exact(&mut file, root.as_mut())?;
    Ok(root)
}

fn print_stage(evidence: &nexora_shield_core::RuntimeStageEvidence) {
    println!("FUNCTIONAL RUNTIME STAGING; production_protected=false");
    println!("Input SHA-256: {}", evidence.input_sha256);
    println!("Output SHA-256: {}", evidence.output_sha256);
    println!("Protected strings: {}", evidence.protected_strings);
    println!("Protected constants: {}", evidence.protected_constants);
    println!("Virtualized methods: {}", evidence.virtualized_methods);
    println!("Protected resources: {}", evidence.protected_resources);
    println!("Rewritten asset calls: {}", evidence.asset_calls);
    println!("Runtime fingerprint: {}", evidence.runtime_fingerprint);
}
