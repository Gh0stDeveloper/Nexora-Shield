use nexora_shield_package::{
    inspect_aab, inspect_aar, inspect_apk_set, verify_aab_structure, verify_aar_structure,
    verify_apk_set_structure, AarMarker, ApkSetMode, Bundletool, BundletoolSigningConfig,
};
use std::path::PathBuf;

pub fn run_aab_inspect(args: &[String]) -> Result<(), String> {
    if args.len() != 1 || help_requested(args) {
        print_aab_help();
        return Ok(());
    }

    let path = PathBuf::from(&args[0]);
    let inspection = inspect_aab(&path).map_err(|error| error.to_string())?;
    println!("AAB: {}", path.display());
    println!("SHA-256: {}", inspection.sha256);
    println!("Entries: {}", inspection.entry_count);
    println!("BundleConfig.pb: {}", inspection.bundle_config_present);
    println!("Modules: {}", inspection.modules.len());
    for module in &inspection.modules {
        println!(
            "  {}: dex={} resources={} res_entries={} assets={} abis={} baseline={}",
            module.name,
            module.dex_files.len(),
            module.resources_table_present,
            module.resource_entries,
            module.asset_entries,
            module.native_abis.len(),
            module.baseline_profile.binary_present
        );
    }
    println!("Dynamic features: {}", inspection.dynamic_features.len());
    Ok(())
}

pub fn run_aab_verify(args: &[String]) -> Result<(), String> {
    if args.len() != 1 || help_requested(args) {
        print_aab_help();
        return Ok(());
    }

    let path = PathBuf::from(&args[0]);
    let inspection = verify_aab_structure(&path).map_err(|error| error.to_string())?;
    println!(
        "AAB structure: OK | modules={} | dynamic_features={} | sha256={}",
        inspection.modules.len(),
        inspection.dynamic_features.len(),
        inspection.sha256
    );
    Ok(())
}

pub fn run_aar_inspect(args: &[String]) -> Result<(), String> {
    if args.len() != 1 || help_requested(args) {
        print_aar_help();
        return Ok(());
    }

    let path = PathBuf::from(&args[0]);
    let inspection = inspect_aar(&path).map_err(|error| error.to_string())?;
    println!("AAR: {}", path.display());
    println!("SHA-256: {}", inspection.sha256);
    println!("Entries: {}", inspection.entry_count);
    println!("Manifest: {}", inspection.has_marker(AarMarker::Manifest));
    println!(
        "classes.jar: {}",
        inspection.has_marker(AarMarker::ClassesJar)
    );
    println!(
        "AAR metadata: {}",
        inspection.has_marker(AarMarker::AarMetadata)
    );
    println!("Consumer rules: {}", inspection.consumer_rule_entries.len());
    println!("Resources: {}", inspection.resource_entries);
    println!(
        "R.txt: {}",
        inspection.has_marker(AarMarker::ResourceSymbols)
    );
    println!(
        "Baseline profiles: {}",
        inspection.baseline_profile_entries.len()
    );
    Ok(())
}

pub fn run_aar_verify(args: &[String]) -> Result<(), String> {
    if args.len() != 1 || help_requested(args) {
        print_aar_help();
        return Ok(());
    }

    let path = PathBuf::from(&args[0]);
    let inspection = verify_aar_structure(&path).map_err(|error| error.to_string())?;
    println!(
        "AAR structure: OK | entries={} | consumer_rules={} | sha256={}",
        inspection.entry_count,
        inspection.consumer_rule_entries.len(),
        inspection.sha256
    );
    Ok(())
}

pub fn run_apks_inspect(args: &[String]) -> Result<(), String> {
    if args.len() != 1 || help_requested(args) {
        print_apks_help();
        return Ok(());
    }

    let path = PathBuf::from(&args[0]);
    let inspection = inspect_apk_set(&path).map_err(|error| error.to_string())?;
    println!("APK Set: {}", path.display());
    println!("SHA-256: {}", inspection.sha256);
    println!("toc.pb: {}", inspection.toc_present);
    println!("APK artifacts: {}", inspection.apks.len());
    for apk in &inspection.apks {
        println!("  {:?}: {}", apk.kind, apk.path);
    }
    Ok(())
}

pub fn run_apks_verify(args: &[String]) -> Result<(), String> {
    if args.len() != 1 || help_requested(args) {
        print_apks_help();
        return Ok(());
    }

    let path = PathBuf::from(&args[0]);
    let inspection = verify_apk_set_structure(&path).map_err(|error| error.to_string())?;
    println!(
        "APK Set structure: OK | apks={} | sha256={}",
        inspection.apks.len(),
        inspection.sha256
    );
    Ok(())
}

pub fn run_bundletool_validate(args: &[String]) -> Result<(), String> {
    if args.is_empty() || help_requested(args) {
        print_bundletool_help();
        return Ok(());
    }

    let bundle = PathBuf::from(&args[0]);
    let mut jar = None;
    let mut java = PathBuf::from("java");
    let mut index = 1_usize;
    while index < args.len() {
        match args[index].as_str() {
            "--jar" => {
                jar = Some(PathBuf::from(require_value(args, index, "--jar")?));
                index += 2;
            }
            "--java" => {
                java = PathBuf::from(require_value(args, index, "--java")?);
                index += 2;
            }
            option => return Err(format!("unknown bundletool-validate option '{option}'")),
        }
    }

    let jar =
        jar.ok_or_else(|| "bundletool-validate requires --jar <bundletool.jar>".to_owned())?;
    verify_aab_structure(&bundle).map_err(|error| error.to_string())?;
    let tool = Bundletool::new(java, jar).map_err(|error| error.to_string())?;
    let diagnostics = tool
        .validate_bundle(&bundle)
        .map_err(|error| error.to_string())?;
    println!("bundletool validation: OK");
    if !diagnostics.trim().is_empty() {
        println!("{diagnostics}");
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub fn run_bundletool_build_apks(args: &[String]) -> Result<(), String> {
    if args.is_empty() || help_requested(args) {
        print_bundletool_help();
        return Ok(());
    }

    let bundle = PathBuf::from(&args[0]);
    let mut jar = None;
    let mut java = PathBuf::from("java");
    let mut output = None;
    let mut mode = ApkSetMode::Default;
    let mut local_testing = false;
    let mut keystore = None;
    let mut alias = None;
    let mut ks_pass_file = None;
    let mut key_pass_file = None;
    let mut index = 1_usize;

    while index < args.len() {
        match args[index].as_str() {
            "--jar" => {
                jar = Some(PathBuf::from(require_value(args, index, "--jar")?));
                index += 2;
            }
            "--java" => {
                java = PathBuf::from(require_value(args, index, "--java")?);
                index += 2;
            }
            "--output" | "-o" => {
                output = Some(PathBuf::from(require_value(args, index, "--output")?));
                index += 2;
            }
            "--mode" => {
                mode = match require_value(args, index, "--mode")? {
                    "default" => ApkSetMode::Default,
                    "universal" => ApkSetMode::Universal,
                    value => return Err(format!("unsupported APK Set mode '{value}'")),
                };
                index += 2;
            }
            "--local-testing" => {
                local_testing = true;
                index += 1;
            }
            "--keystore" => {
                keystore = Some(PathBuf::from(require_value(args, index, "--keystore")?));
                index += 2;
            }
            "--alias" => {
                alias = Some(require_value(args, index, "--alias")?.to_owned());
                index += 2;
            }
            "--ks-pass-file" => {
                ks_pass_file = Some(PathBuf::from(require_value(args, index, "--ks-pass-file")?));
                index += 2;
            }
            "--key-pass-file" => {
                key_pass_file = Some(PathBuf::from(require_value(
                    args,
                    index,
                    "--key-pass-file",
                )?));
                index += 2;
            }
            option => return Err(format!("unknown bundletool-build-apks option '{option}'")),
        }
    }

    let jar =
        jar.ok_or_else(|| "bundletool-build-apks requires --jar <bundletool.jar>".to_owned())?;
    let output =
        output.ok_or_else(|| "bundletool-build-apks requires --output <file.apks>".to_owned())?;

    verify_aab_structure(&bundle).map_err(|error| error.to_string())?;

    let signing = if let Some(keystore) = keystore {
        Some(BundletoolSigningConfig {
            keystore,
            key_alias: alias.ok_or_else(|| "--keystore requires --alias".to_owned())?,
            keystore_password_file: ks_pass_file
                .ok_or_else(|| "--keystore requires --ks-pass-file".to_owned())?,
            key_password_file: key_pass_file,
        })
    } else {
        if alias.is_some() || ks_pass_file.is_some() || key_pass_file.is_some() {
            return Err("bundletool signing options require --keystore".into());
        }
        None
    };

    let tool = Bundletool::new(java, jar).map_err(|error| error.to_string())?;
    let diagnostics = tool
        .build_apks(&bundle, &output, mode, local_testing, signing.as_ref())
        .map_err(|error| error.to_string())?;
    let inspection = verify_apk_set_structure(&output).map_err(|error| error.to_string())?;

    println!(
        "bundletool build-apks: OK | apks={} | sha256={}",
        inspection.apks.len(),
        inspection.sha256
    );
    if !diagnostics.trim().is_empty() {
        println!("{diagnostics}");
    }
    Ok(())
}

pub fn print_phase_k_help() {
    println!(
        "Phase K commands:\n\
  aab-inspect <app.aab>\n\
  aab-verify <app.aab>\n\
  aar-inspect <library.aar>\n\
  aar-verify <library.aar>\n\
  apks-inspect <set.apks>\n\
  apks-verify <set.apks>\n\
  bundletool-validate <app.aab> --jar <bundletool.jar> [--java <java>]\n\
  bundletool-build-apks <app.aab> --jar <bundletool.jar> --output <set.apks> [OPTIONS]"
    );
}

fn print_aab_help() {
    println!("USAGE:\n  nexora-shield aab-inspect <app.aab>\n  nexora-shield aab-verify <app.aab>");
}

fn print_aar_help() {
    println!(
        "USAGE:\n  nexora-shield aar-inspect <library.aar>\n  nexora-shield aar-verify <library.aar>"
    );
}

fn print_apks_help() {
    println!(
        "USAGE:\n  nexora-shield apks-inspect <set.apks>\n  nexora-shield apks-verify <set.apks>"
    );
}

fn print_bundletool_help() {
    println!(
        "USAGE:\n  nexora-shield bundletool-validate <app.aab> --jar <bundletool.jar> [--java <java>]\n  nexora-shield bundletool-build-apks <app.aab> --jar <bundletool.jar> --output <set.apks> [OPTIONS]\n\nOPTIONS:\n  --mode default|universal\n  --local-testing\n  --keystore <file> --alias <name> --ks-pass-file <file> [--key-pass-file <file>]"
    );
}

fn help_requested(args: &[String]) -> bool {
    args.iter().any(|value| value == "--help" || value == "-h")
}

fn require_value<'a>(args: &'a [String], index: usize, option: &str) -> Result<&'a str, String> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("{option} requires a value"))
}
