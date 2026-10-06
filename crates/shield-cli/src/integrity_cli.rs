use nexora_shield_integrity::{
    ArtifactIntegrity, ArtifactKind, CertificateBinding, CertificateObservation, CertificatePolicy,
    DexIntegrity, IntegrityEvidence, IntegrityManifest, IntegrityVerifier, PackageBinding,
    PackageObservation, ResponsePolicy, Sha256Digest, DEFAULT_DEX_CHUNK_BYTES,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub(crate) fn run_integrity_create(args: &[String]) -> Result<(), String> {
    if args.is_empty() || wants_help(args) {
        print_integrity_create_help();
        return Ok(());
    }

    let mut output = None;
    let mut build_id = None;
    let mut application_id = None;
    let mut version_code = None;
    let mut split_name = None;
    let mut signer_digests = Vec::new();
    let mut lineage_digests = Vec::new();
    let mut certificate_policy = CertificatePolicy::ExactCurrent;
    let mut dex_specs = Vec::new();
    let mut resource_specs = Vec::new();
    let mut native_specs = Vec::new();
    let mut seed = b"nexora-shield-phase-d-default-seed".to_vec();
    let mut checks = 5_u32;
    let mut redundancy = 2_u8;
    let mut chunk_bytes = DEFAULT_DEX_CHUNK_BYTES;

    let mut index = 0_usize;
    while index < args.len() {
        match args[index].as_str() {
            "-o" | "--output" => {
                output = Some(PathBuf::from(require_value(args, index, "--output")?));
                index += 2;
            }
            "--build-id" => {
                build_id = Some(require_value(args, index, "--build-id")?.to_owned());
                index += 2;
            }
            "--app-id" => {
                application_id = Some(require_value(args, index, "--app-id")?.to_owned());
                index += 2;
            }
            "--version-code" => {
                version_code = Some(parse_u64(
                    require_value(args, index, "--version-code")?,
                    "--version-code",
                )?);
                index += 2;
            }
            "--split" => {
                split_name = Some(require_value(args, index, "--split")?.to_owned());
                index += 2;
            }
            "--signer-sha256" => {
                signer_digests.push(parse_digest(require_value(
                    args,
                    index,
                    "--signer-sha256",
                )?)?);
                index += 2;
            }
            "--lineage-sha256" => {
                lineage_digests.push(parse_digest(require_value(
                    args,
                    index,
                    "--lineage-sha256",
                )?)?);
                index += 2;
            }
            "--allow-lineage" => {
                certificate_policy = CertificatePolicy::CurrentOrLineage;
                index += 1;
            }
            "--dex" => {
                dex_specs.push(parse_mapping(
                    require_value(args, index, "--dex")?,
                    "--dex",
                )?);
                index += 2;
            }
            "--resource" => {
                resource_specs.push(parse_mapping(
                    require_value(args, index, "--resource")?,
                    "--resource",
                )?);
                index += 2;
            }
            "--native" => {
                native_specs.push(parse_mapping(
                    require_value(args, index, "--native")?,
                    "--native",
                )?);
                index += 2;
            }
            "--seed" => {
                seed = require_value(args, index, "--seed")?.as_bytes().to_vec();
                index += 2;
            }
            "--checks" => {
                checks = parse_u32(require_value(args, index, "--checks")?, "--checks")?;
                index += 2;
            }
            "--redundancy" => {
                redundancy = parse_u8(require_value(args, index, "--redundancy")?, "--redundancy")?;
                index += 2;
            }
            "--dex-chunk-bytes" => {
                chunk_bytes = parse_u32(
                    require_value(args, index, "--dex-chunk-bytes")?,
                    "--dex-chunk-bytes",
                )?;
                index += 2;
            }
            option => return Err(format!("unknown integrity-create option '{option}'")),
        }
    }

    let output =
        output.ok_or_else(|| "integrity-create requires --output <manifest.json>".to_owned())?;
    let build_id = build_id.ok_or_else(|| "integrity-create requires --build-id".to_owned())?;
    let application_id =
        application_id.ok_or_else(|| "integrity-create requires --app-id".to_owned())?;
    let version_code =
        version_code.ok_or_else(|| "integrity-create requires --version-code".to_owned())?;
    if signer_digests.is_empty() {
        return Err("integrity-create requires at least one --signer-sha256".into());
    }

    let certificate = CertificateBinding::new(certificate_policy, signer_digests, lineage_digests)
        .map_err(|error| error.to_string())?;
    let package = PackageBinding::new(application_id, version_code, split_name)
        .map_err(|error| error.to_string())?;

    let mut dex_files = Vec::with_capacity(dex_specs.len());
    for (logical, path) in dex_specs {
        let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        dex_files.push(
            DexIntegrity::build(logical, &bytes, chunk_bytes).map_err(|error| error.to_string())?,
        );
    }

    let mut artifacts = Vec::with_capacity(resource_specs.len() + native_specs.len());
    for (logical, path) in resource_specs {
        let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        artifacts.push(
            ArtifactIntegrity::build(logical, ArtifactKind::Resource, &bytes)
                .map_err(|error| error.to_string())?,
        );
    }
    for (logical, path) in native_specs {
        let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        artifacts.push(
            ArtifactIntegrity::build(logical, ArtifactKind::Native, &bytes)
                .map_err(|error| error.to_string())?,
        );
    }

    let manifest = IntegrityManifest::build(IntegrityManifestInput {
        build_id,
        certificate,
        package,
        dex_files,
        artifacts,
        distribution: DistributionConfig::new(seed, checks, redundancy),
        response_policy: ResponsePolicy::default(),
    })
    .map_err(|error| error.to_string())?;
    let json = manifest
        .to_json_pretty()
        .map_err(|error| error.to_string())?;
    write_atomic(&output, json.as_bytes())?;

    println!("Integrity manifest: OK");
    println!("Output: {}", output.display());
    println!("Graph root: {}", manifest.graph.root);
    println!("Graph nodes: {}", manifest.graph.nodes.len());
    println!("Distributed checks: {}", manifest.distribution.checks.len());
    println!("Redundancy: {}", manifest.distribution.redundancy);
    Ok(())
}

pub(crate) fn run_integrity_verify(args: &[String]) -> Result<(), String> {
    if args.is_empty() || wants_help(args) {
        print_integrity_verify_help();
        return Ok(());
    }

    let manifest_path = PathBuf::from(&args[0]);
    let mut current_signers = Vec::new();
    let mut lineage = Vec::new();
    let mut application_id = None;
    let mut version_code = None;
    let mut split_name = None;
    let mut dex_specs = Vec::new();
    let mut artifact_specs = Vec::new();
    let mut check_id = None;

    let mut index = 1_usize;
    while index < args.len() {
        match args[index].as_str() {
            "--observed-signer-sha256" => {
                current_signers.push(parse_digest(require_value(
                    args,
                    index,
                    "--observed-signer-sha256",
                )?)?);
                index += 2;
            }
            "--observed-lineage-sha256" => {
                lineage.push(parse_digest(require_value(
                    args,
                    index,
                    "--observed-lineage-sha256",
                )?)?);
                index += 2;
            }
            "--app-id" => {
                application_id = Some(require_value(args, index, "--app-id")?.to_owned());
                index += 2;
            }
            "--version-code" => {
                version_code = Some(parse_u64(
                    require_value(args, index, "--version-code")?,
                    "--version-code",
                )?);
                index += 2;
            }
            "--split" => {
                split_name = Some(require_value(args, index, "--split")?.to_owned());
                index += 2;
            }
            "--dex" => {
                dex_specs.push(parse_mapping(
                    require_value(args, index, "--dex")?,
                    "--dex",
                )?);
                index += 2;
            }
            "--artifact" => {
                artifact_specs.push(parse_mapping(
                    require_value(args, index, "--artifact")?,
                    "--artifact",
                )?);
                index += 2;
            }
            "--check-id" => {
                check_id = Some(parse_u32(
                    require_value(args, index, "--check-id")?,
                    "--check-id",
                )?);
                index += 2;
            }
            option => return Err(format!("unknown integrity-verify option '{option}'")),
        }
    }

    if current_signers.is_empty() {
        return Err("integrity-verify requires --observed-signer-sha256".into());
    }
    let application_id =
        application_id.ok_or_else(|| "integrity-verify requires --app-id".to_owned())?;
    let version_code =
        version_code.ok_or_else(|| "integrity-verify requires --version-code".to_owned())?;

    let json = fs::read_to_string(&manifest_path)
        .map_err(|error| format!("{}: {error}", manifest_path.display()))?;
    let manifest = IntegrityManifest::from_json(&json).map_err(|error| error.to_string())?;

    let certificate =
        CertificateObservation::new(current_signers, lineage).map_err(|error| error.to_string())?;
    let package = PackageObservation::new(application_id, version_code, split_name)
        .map_err(|error| error.to_string())?;

    let mut dex_files = BTreeMap::new();
    for (logical, path) in dex_specs {
        let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        if dex_files.insert(logical.clone(), bytes).is_some() {
            return Err(format!("duplicate DEX evidence '{logical}'"));
        }
    }
    let mut artifacts = BTreeMap::new();
    for (logical, path) in artifact_specs {
        let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        if artifacts.insert(logical.clone(), bytes).is_some() {
            return Err(format!("duplicate artifact evidence '{logical}'"));
        }
    }

    let evidence = IntegrityEvidence {
        certificate,
        package,
        dex_files,
        artifacts,
    };
    let verdict = match check_id {
        Some(id) => IntegrityVerifier::verify_check(&manifest, &evidence, id),
        None => IntegrityVerifier::verify_all(&manifest, &evidence),
    }
    .map_err(|error| error.to_string())?;

    println!("Integrity clean: {}", verdict.clean);
    println!("Severity: {:?}", verdict.severity);
    println!("Response: {:?}", verdict.response);
    println!(
        "Checks: {}/{} passed",
        verdict.checks_passed, verdict.checks_total
    );
    for failure in &verdict.failures {
        println!(
            "FAIL {:?} {} expected={} observed={} reason={}",
            failure.kind,
            failure.label,
            failure.expected,
            failure
                .observed
                .map_or_else(|| "<missing>".to_owned(), |digest| digest.to_string()),
            failure.reason
        );
    }

    if verdict.clean {
        Ok(())
    } else {
        Err(format!(
            "integrity verification failed with {:?}",
            verdict.response
        ))
    }
}

pub(crate) fn run_integrity_inspect(args: &[String]) -> Result<(), String> {
    if args.len() != 1 || wants_help(args) {
        print_integrity_inspect_help();
        return Ok(());
    }
    let path = PathBuf::from(&args[0]);
    let json = fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let manifest = IntegrityManifest::from_json(&json).map_err(|error| error.to_string())?;

    println!("Integrity manifest: {}", path.display());
    println!("Schema: {}", manifest.schema);
    println!("Build ID: {}", manifest.build_id);
    println!("Application ID: {}", manifest.package.application_id);
    println!("Version code: {}", manifest.package.version_code);
    println!("DEX files: {}", manifest.dex_files.len());
    println!("Artifacts: {}", manifest.artifacts.len());
    println!("Graph nodes: {}", manifest.graph.nodes.len());
    println!("Graph edges: {}", manifest.graph.edges.len());
    println!("Graph root: {}", manifest.graph.root);
    println!("Distributed checks: {}", manifest.distribution.checks.len());
    println!("Redundancy: {}", manifest.distribution.redundancy);
    Ok(())
}

pub(crate) fn print_integrity_help() {
    println!(
        "Phase D integrity commands:\n\
  integrity-create   Build certificate/package/content integrity manifest\n\
  integrity-verify   Verify full or distributed integrity evidence\n\
  integrity-inspect  Validate and inspect an integrity manifest"
    );
}

fn parse_mapping(value: &str, option: &str) -> Result<(String, PathBuf), String> {
    let (logical, path) = value
        .split_once('=')
        .ok_or_else(|| format!("{option} expects <logical-name>=<file>"))?;
    if logical.is_empty() || path.is_empty() {
        return Err(format!("{option} expects non-empty logical name and file"));
    }
    Ok((logical.to_owned(), PathBuf::from(path)))
}

fn parse_digest(value: &str) -> Result<Sha256Digest, String> {
    Sha256Digest::from_str(value).map_err(|error| error.to_string())
}

fn parse_u32(value: &str, option: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("{option} expects an unsigned integer, got '{value}'"))
}

fn parse_u64(value: &str, option: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{option} expects an unsigned integer, got '{value}'"))
}

fn parse_u8(value: &str, option: &str) -> Result<u8, String> {
    value
        .parse::<u8>()
        .map_err(|_| format!("{option} expects an integer from 0 to 255, got '{value}'"))
}

fn require_value<'a>(args: &'a [String], index: usize, option: &str) -> Result<&'a str, String> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("{option} requires a value"))
}

fn wants_help(args: &[String]) -> bool {
    args.iter().any(|value| value == "--help" || value == "-h")
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
    if path.exists() {
        fs::remove_file(path).map_err(|error| error.to_string())?;
    }
    fs::rename(&temporary, path).map_err(|error| error.to_string())
}

fn print_integrity_create_help() {
    println!(
        "USAGE:\n  nexora-shield integrity-create --output <manifest.json> \\\n\
    --build-id <id> --app-id <package> --version-code <code> \\\n\
    --signer-sha256 <hex> [--lineage-sha256 <hex>] [--allow-lineage] \\\n\
    [--dex <logical=file>] [--resource <logical=file>] [--native <logical=file>] \\\n\
    [--seed <text>] [--checks <n>] [--redundancy <n>] [--dex-chunk-bytes <n>]"
    );
}

fn print_integrity_verify_help() {
    println!(
        "USAGE:\n  nexora-shield integrity-verify <manifest.json> \\\n\
    --observed-signer-sha256 <hex> --app-id <package> --version-code <code> \\\n\
    [--observed-lineage-sha256 <hex>] [--dex <logical=file>] \\\n\
    [--artifact <logical=file>] [--check-id <id>]"
    );
}

fn print_integrity_inspect_help() {
    println!("USAGE:\n  nexora-shield integrity-inspect <manifest.json>");
}
