//! Nexora Shield command-line entry point.

#![forbid(unsafe_code)]

use nexora_shield_core::{
    apk_inspection_json, protect_apk, ProtectionProfile, ProtectionRequest, CONFIG_SCHEMA_VERSION,
};
use nexora_shield_package::{inspect_apk, verify_apk_structure, AndroidTools, SigningConfig};
use std::path::{Path, PathBuf};
use std::str::FromStr;

fn main() {
    if let Err(error) = run() {
        eprintln!("nexora-shield: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_help();
        return Ok(());
    }

    let command = args.remove(0);
    match command.as_str() {
        "-h" | "--help" | "help" => {
            print_help();
            Ok(())
        }
        "-V" | "--version" => {
            println!("nexora-shield {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "profiles" => {
            print_profiles();
            Ok(())
        }
        "inspect" => run_inspect(&args),
        "verify" => run_verify(&args),
        "protect" => run_protect(&args),
        _ => Err(format!(
            "unknown command '{command}'. Run 'nexora-shield --help'."
        )),
    }
}

fn run_inspect(args: &[String]) -> Result<(), String> {
    if args.is_empty() || args.iter().any(|value| value == "--help" || value == "-h") {
        print_inspect_help();
        return Ok(());
    }

    let input = PathBuf::from(&args[0]);
    let json = args.iter().skip(1).any(|value| value == "--json");
    for option in args.iter().skip(1) {
        if option != "--json" {
            return Err(format!("unknown inspect option '{option}'"));
        }
    }

    let inspection = inspect_apk(&input).map_err(|error| error.to_string())?;
    if json {
        print!("{}", apk_inspection_json(&inspection));
    } else {
        print_inspection(&input, &inspection);
    }
    Ok(())
}

fn run_verify(args: &[String]) -> Result<(), String> {
    if args.is_empty() || args.iter().any(|value| value == "--help" || value == "-h") {
        print_verify_help();
        return Ok(());
    }

    let input = PathBuf::from(&args[0]);
    let mut signature = false;
    let mut apksigner = None;
    let mut zipalign = None;
    let mut min_sdk = 24_u32;
    let mut index = 1_usize;

    while index < args.len() {
        match args[index].as_str() {
            "--signature" => {
                signature = true;
                index += 1;
            }
            "--apksigner" => {
                apksigner = Some(PathBuf::from(require_value(args, index, "--apksigner")?));
                index += 2;
            }
            "--zipalign" => {
                zipalign = Some(PathBuf::from(require_value(args, index, "--zipalign")?));
                index += 2;
            }
            "--min-sdk" => {
                min_sdk = parse_u32(require_value(args, index, "--min-sdk")?, "--min-sdk")?;
                index += 2;
            }
            option => return Err(format!("unknown verify option '{option}'")),
        }
    }

    let inspection = verify_apk_structure(&input).map_err(|error| error.to_string())?;
    println!(
        "APK structure: OK | entries={} | dex={} | sha256={}",
        inspection.entry_count,
        inspection.dex_files.len(),
        inspection.sha256
    );

    if signature {
        let tools = AndroidTools::discover(zipalign.as_deref(), apksigner.as_deref())
            .map_err(|error| error.to_string())?;
        let details = tools
            .verify_signature(&input, min_sdk)
            .map_err(|error| error.to_string())?;
        println!("APK signature: OK");
        if !details.trim().is_empty() {
            println!("{details}");
        }
    }

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_protect(args: &[String]) -> Result<(), String> {
    if args.is_empty() || args.iter().any(|value| value == "--help" || value == "-h") {
        print_protect_help();
        return Ok(());
    }

    let input = PathBuf::from(&args[0]);
    let mut output = None;
    let mut profile = ProtectionProfile::Hardened;
    let mut align = true;
    let mut allow_unsigned = false;
    let mut overwrite = false;
    let mut zipalign = None;
    let mut apksigner = None;
    let mut keystore = None;
    let mut alias = None;
    let mut ks_pass_env = None;
    let mut key_pass_env = None;
    let mut min_sdk = 24_u32;
    let mut public_report = None;
    let mut private_report = None;
    let mut index = 1_usize;

    while index < args.len() {
        match args[index].as_str() {
            "-o" | "--output" => {
                output = Some(PathBuf::from(require_value(args, index, "--output")?));
                index += 2;
            }
            "--profile" => {
                let value = require_value(args, index, "--profile")?;
                profile = ProtectionProfile::from_str(value)
                    .map_err(|error| format!("{error}: '{value}'"))?;
                index += 2;
            }
            "--no-align" => {
                align = false;
                index += 1;
            }
            "--unsigned" => {
                allow_unsigned = true;
                index += 1;
            }
            "--force" => {
                overwrite = true;
                index += 1;
            }
            "--zipalign" => {
                zipalign = Some(PathBuf::from(require_value(args, index, "--zipalign")?));
                index += 2;
            }
            "--apksigner" => {
                apksigner = Some(PathBuf::from(require_value(args, index, "--apksigner")?));
                index += 2;
            }
            "--keystore" => {
                keystore = Some(PathBuf::from(require_value(args, index, "--keystore")?));
                index += 2;
            }
            "--alias" => {
                alias = Some(require_value(args, index, "--alias")?.to_owned());
                index += 2;
            }
            "--ks-pass-env" => {
                ks_pass_env = Some(require_value(args, index, "--ks-pass-env")?.to_owned());
                index += 2;
            }
            "--key-pass-env" => {
                key_pass_env = Some(require_value(args, index, "--key-pass-env")?.to_owned());
                index += 2;
            }
            "--min-sdk" => {
                min_sdk = parse_u32(require_value(args, index, "--min-sdk")?, "--min-sdk")?;
                index += 2;
            }
            "--public-report" => {
                public_report = Some(PathBuf::from(require_value(
                    args,
                    index,
                    "--public-report",
                )?));
                index += 2;
            }
            "--private-report" => {
                private_report = Some(PathBuf::from(require_value(
                    args,
                    index,
                    "--private-report",
                )?));
                index += 2;
            }
            option => return Err(format!("unknown protect option '{option}'")),
        }
    }

    let output = output.ok_or_else(|| "protect requires --output <apk>".to_owned())?;

    if allow_unsigned && keystore.is_some() {
        return Err("--unsigned cannot be combined with --keystore".into());
    }

    let signing = if let Some(keystore) = keystore {
        let key_alias = alias.ok_or_else(|| "--keystore requires --alias".to_owned())?;
        let keystore_password_env =
            ks_pass_env.ok_or_else(|| "--keystore requires --ks-pass-env".to_owned())?;
        let key_password_env = key_pass_env.or_else(|| Some(keystore_password_env.clone()));

        Some(SigningConfig {
            keystore,
            key_alias,
            keystore_password_env,
            key_password_env,
            min_sdk,
            v1: true,
            v2: true,
            v3: true,
        })
    } else {
        if alias.is_some() || ks_pass_env.is_some() || key_pass_env.is_some() {
            return Err("signing options require --keystore".into());
        }
        None
    };

    let request = ProtectionRequest {
        input,
        output,
        profile,
        align,
        allow_unsigned,
        overwrite,
        signing,
        zipalign,
        apksigner,
        public_report,
        private_report,
    };

    let result = protect_apk(&request).map_err(|error| error.to_string())?;
    println!("Nexora Shield Phase A protection pipeline: OK");
    println!("Build ID: {}", result.plan.build_id);
    println!("Output: {}", result.plan.output.display());
    println!("SHA-256: {}", result.output_inspection.sha256);
    println!("DEX files: {}", result.output_inspection.dex_files.len());
    println!("Aligned: {}", result.aligned);
    println!("Signed: {}", result.signed);
    println!(
        "Removed stale signature entries: {}",
        result.normalization.stripped_signature_entries.len()
    );
    Ok(())
}

fn require_value<'a>(args: &'a [String], index: usize, option: &str) -> Result<&'a str, String> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("{option} requires a value"))
}

fn parse_u32(value: &str, option: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("{option} expects an unsigned integer, got '{value}'"))
}

fn print_inspection(path: &Path, inspection: &nexora_shield_package::ApkInspection) {
    println!("APK: {}", path.display());
    println!("SHA-256: {}", inspection.sha256);
    println!("Size: {} bytes", inspection.file_size);
    println!("Entries: {}", inspection.entry_count);
    println!(
        "Manifest: {} | method={} | size={} bytes",
        inspection.manifest.format.as_str(),
        inspection.manifest.compression_method,
        inspection.manifest.uncompressed_size
    );
    println!("DEX files: {}", inspection.dex_files.len());
    for dex in &inspection.dex_files {
        println!(
            "  {} (index {}, {} bytes)",
            dex.name, dex.index, dex.uncompressed_size
        );
    }
    println!(
        "DEX sequence contiguous: {}",
        inspection.dex_sequence_contiguous
    );
    println!(
        "Legacy signature entries: {}",
        inspection.legacy_signature_entries.len()
    );
}

fn print_profiles() {
    for profile in [
        ProtectionProfile::Standard,
        ProtectionProfile::Hardened,
        ProtectionProfile::Maximum,
    ] {
        println!("{profile}");
    }
}

fn print_help() {
    println!(
        "Nexora Shield {}\n\n\
Android application protection and RASP platform.\n\n\
USAGE:\n  nexora-shield <COMMAND> [OPTIONS]\n\n\
COMMANDS:\n\
  protect      Normalize, align, sign and verify an APK\n\
  inspect      Inspect APK structure, manifest and multi-DEX layout\n\
  verify       Verify APK structure and optionally Android signatures\n\
  profiles     List stable protection profiles\n\n\
OPTIONS:\n\
  -h, --help       Print help\n\
  -V, --version    Print version\n\n\
Configuration schema: {}",
        env!("CARGO_PKG_VERSION"),
        CONFIG_SCHEMA_VERSION
    );
}

fn print_inspect_help() {
    println!(
        "USAGE:\n  nexora-shield inspect <app.apk> [--json]\n\n\
Inspects the ZIP structure, AndroidManifest.xml metadata, classes*.dex layout and stale v1 signature entries."
    );
}

fn print_verify_help() {
    println!(
        "USAGE:\n  nexora-shield verify <app.apk> [OPTIONS]\n\n\
OPTIONS:\n\
  --signature           Verify signing schemes using official apksigner\n\
  --apksigner <path>    Explicit apksigner path\n\
  --zipalign <path>     Explicit zipalign path used during SDK tool discovery\n\
  --min-sdk <api>       Minimum SDK passed to apksigner (default: 24)"
    );
}

fn print_protect_help() {
    println!(
        "USAGE:\n  nexora-shield protect <input.apk> --output <output.apk> [OPTIONS]\n\n\
By default Nexora Shield requires signing and alignment. Use --unsigned only when an unsigned artifact is intentional.\n\n\
OPTIONS:\n\
  -o, --output <apk>          Output APK\n\
  --profile <name>            standard|hardened|maximum (default: hardened)\n\
  --keystore <file>           Signing keystore\n\
  --alias <name>              Signing key alias\n\
  --ks-pass-env <name>        Environment variable containing keystore password\n\
  --key-pass-env <name>       Environment variable containing key password\n\
  --min-sdk <api>             Minimum SDK for signing (default: 24)\n\
  --zipalign <path>           Explicit official zipalign path\n\
  --apksigner <path>          Explicit official apksigner path\n\
  --no-align                  Skip zipalign explicitly\n\
  --unsigned                  Explicitly allow an unsigned output\n\
  --force                     Replace an existing output transactionally\n\
  --public-report <file>      Write non-sensitive JSON report\n\
  --private-report <file>     Write private build JSON report"
    );
}
