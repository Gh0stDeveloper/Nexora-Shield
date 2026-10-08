//! Nexora Shield command-line entry point.

#![forbid(unsafe_code)]

mod data_cli;
mod integrity_cli;
mod phase_k_cli;

use data_cli::{
    print_data_help, run_data_benchmark, run_data_inspect, run_data_protect, run_data_unprotect,
};
use integrity_cli::{
    print_integrity_help, run_integrity_create, run_integrity_inspect, run_integrity_verify,
};
use phase_k_cli::{
    print_phase_k_help, run_aab_inspect, run_aab_verify, run_aar_inspect, run_aar_verify,
    run_apks_inspect, run_apks_verify, run_bundletool_build_apks, run_bundletool_validate,
};

use nexora_shield_core::{
    apk_inspection_json, protect_apk, protect_production_apk, ProductionBuildContext,
    ProtectionProfile, ProtectionRequest,
    CONFIG_SCHEMA_VERSION,
};
use nexora_shield_dex::{
    CompatibilityAnalyzer, ControlFlowGraph, DexInput, DexParser, DexValidator, DexWriter,
    IrMethod, MetadataReducer, MultiDexSet, ReferenceGraph, RenameConfig, RenamePass, Selector,
    SelectorKind, TypeAnalyzer,
};
use nexora_shield_package::{inspect_apk, verify_apk_structure, AndroidTools, SigningConfig};
use std::fs;
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
        "protect" => run_protect(&args, false),
        "package-apk" => run_protect(&args, true),
        "aab-inspect" => run_aab_inspect(&args),
        "aab-verify" => run_aab_verify(&args),
        "aar-inspect" => run_aar_inspect(&args),
        "aar-verify" => run_aar_verify(&args),
        "apks-inspect" => run_apks_inspect(&args),
        "apks-verify" => run_apks_verify(&args),
        "bundletool-validate" => run_bundletool_validate(&args),
        "bundletool-build-apks" => run_bundletool_build_apks(&args),
        "phase-k-help" => {
            print_phase_k_help();
            Ok(())
        }
        "dex-inspect" => run_dex_inspect(&args),
        "dex-roundtrip" => run_dex_roundtrip(&args),
        "dex-rewrite" => run_dex_rewrite(&args),
        "dex-multidex-verify" => run_dex_multidex_verify(&args),
        "data-protect" => run_data_protect(&args),
        "data-unprotect" => run_data_unprotect(&args),
        "data-inspect" => run_data_inspect(&args),
        "data-benchmark" => run_data_benchmark(&args),
        "data-help" => {
            print_data_help();
            Ok(())
        }
        "integrity-create" => run_integrity_create(&args),
        "integrity-verify" => run_integrity_verify(&args),
        "integrity-inspect" => run_integrity_inspect(&args),
        "integrity-help" => {
            print_integrity_help();
            Ok(())
        }
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

fn run_dex_inspect(args: &[String]) -> Result<(), String> {
    if args.len() != 1 || args.iter().any(|value| value == "--help" || value == "-h") {
        print_dex_inspect_help();
        return Ok(());
    }

    let path = PathBuf::from(&args[0]);
    let bytes = fs::read(&path).map_err(|error| error.to_string())?;
    let dex = DexParser::parse(&bytes).map_err(|error| error.to_string())?;
    let validation = DexValidator::validate(&dex).map_err(|error| error.to_string())?;
    let graph = ReferenceGraph::build(&dex);
    let compatibility = CompatibilityAnalyzer::analyze(&dex).map_err(|error| error.to_string())?;

    let mut cfg_blocks = 0_usize;
    let mut ir_blocks = 0_usize;
    let mut phi_nodes = 0_usize;
    for data in dex.class_data.values() {
        for method in data.methods().filter(|method| method.code_off != 0) {
            let code = dex
                .code_items
                .get(&method.code_off)
                .ok_or_else(|| format!("missing code_item at {}", method.code_off))?;
            cfg_blocks += ControlFlowGraph::build(code)
                .map_err(|error| error.to_string())?
                .blocks
                .len();
            let _ = TypeAnalyzer::analyze(&dex, method.method_idx)
                .map_err(|error| error.to_string())?;
            let ir = IrMethod::build(&dex, method.method_idx).map_err(|error| error.to_string())?;
            ir_blocks += ir.blocks.len();
            phi_nodes += ir
                .blocks
                .iter()
                .map(|block| block.phis.len())
                .sum::<usize>();
        }
    }

    println!("DEX: {}", path.display());
    println!("Version: {}", dex.header.version);
    println!("Classes: {}", validation.classes);
    println!("Methods: {}", validation.methods);
    println!("Fields: {}", dex.fields.len());
    println!("Code items: {}", validation.code_items);
    println!("Instructions: {}", validation.instructions);
    println!("CFG blocks: {cfg_blocks}");
    println!("IR blocks: {ir_blocks}");
    println!("SSA phi nodes: {phi_nodes}");
    println!("Reference graph nodes: {}", graph.nodes.len());
    println!("Reference graph edges: {}", graph.edges.len());
    println!("Reflection evidence: {}", compatibility.reflection_detected);
    println!("Native methods: {}", compatibility.native_methods.len());
    Ok(())
}

fn run_dex_roundtrip(args: &[String]) -> Result<(), String> {
    if args.is_empty() || args.iter().any(|value| value == "--help" || value == "-h") {
        print_dex_roundtrip_help();
        return Ok(());
    }

    let input = PathBuf::from(&args[0]);
    let mut output = None;
    let mut index = 1_usize;
    while index < args.len() {
        match args[index].as_str() {
            "-o" | "--output" => {
                output = Some(PathBuf::from(require_value(args, index, "--output")?));
                index += 2;
            }
            option => return Err(format!("unknown dex-roundtrip option '{option}'")),
        }
    }
    let output = output.ok_or_else(|| "dex-roundtrip requires --output <file.dex>".to_owned())?;

    let bytes = fs::read(&input).map_err(|error| error.to_string())?;
    let dex = DexParser::parse(&bytes).map_err(|error| error.to_string())?;
    let _ = DexValidator::validate(&dex).map_err(|error| error.to_string())?;
    let rewritten = DexWriter::round_trip(&dex).map_err(|error| error.to_string())?;
    fs::write(&output, &rewritten).map_err(|error| error.to_string())?;
    let reparsed = DexParser::parse(&rewritten).map_err(|error| error.to_string())?;
    let _ = DexValidator::validate(&reparsed).map_err(|error| error.to_string())?;

    println!("DEX round-trip: OK");
    println!("Input: {}", input.display());
    println!("Output: {}", output.display());
    println!("Byte-stable: {}", bytes == rewritten);
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_dex_rewrite(args: &[String]) -> Result<(), String> {
    if args.is_empty() || args.iter().any(|value| value == "--help" || value == "-h") {
        print_dex_rewrite_help();
        return Ok(());
    }

    let input = PathBuf::from(&args[0]);
    let mut output = None;
    let mut rename = false;
    let mut strip_metadata = false;
    let mut seed = RenameConfig::default().seed;
    let mut selectors = Vec::new();
    let mut index = 1_usize;

    while index < args.len() {
        match args[index].as_str() {
            "-o" | "--output" => {
                output = Some(PathBuf::from(require_value(args, index, "--output")?));
                index += 2;
            }
            "--rename" => {
                rename = true;
                index += 1;
            }
            "--strip-metadata" => {
                strip_metadata = true;
                index += 1;
            }
            "--seed" => {
                seed = parse_u64(require_value(args, index, "--seed")?, "--seed")?;
                index += 2;
            }
            "--class" => {
                let pattern = require_value(args, index, "--class")?;
                selectors.push(
                    Selector::new(SelectorKind::Class, pattern, None)
                        .map_err(|error| error.to_string())?,
                );
                index += 2;
            }
            "--method" => {
                let value = require_value(args, index, "--method")?;
                let (class_pattern, member_pattern) = split_member_selector(value, "--method")?;
                selectors.push(
                    Selector::new(
                        SelectorKind::Method,
                        class_pattern,
                        Some(member_pattern.to_owned()),
                    )
                    .map_err(|error| error.to_string())?,
                );
                index += 2;
            }
            "--field" => {
                let value = require_value(args, index, "--field")?;
                let (class_pattern, member_pattern) = split_member_selector(value, "--field")?;
                selectors.push(
                    Selector::new(
                        SelectorKind::Field,
                        class_pattern,
                        Some(member_pattern.to_owned()),
                    )
                    .map_err(|error| error.to_string())?,
                );
                index += 2;
            }
            option => return Err(format!("unknown dex-rewrite option '{option}'")),
        }
    }

    if !rename && !strip_metadata {
        return Err("dex-rewrite requires --rename and/or --strip-metadata".into());
    }
    let output = output.ok_or_else(|| "dex-rewrite requires --output <file.dex>".to_owned())?;

    let bytes = fs::read(&input).map_err(|error| error.to_string())?;
    let mut dex = DexParser::parse(&bytes).map_err(|error| error.to_string())?;
    let _ = DexValidator::validate(&dex).map_err(|error| error.to_string())?;
    let mut current = bytes;
    let mut renamed = 0_usize;

    if rename {
        let result = RenamePass::apply(
            &dex,
            &RenameConfig {
                selectors,
                seed,
                ..RenameConfig::default()
            },
        )
        .map_err(|error| error.to_string())?;
        renamed = result.report.records.len();
        current = result.bytes;
        dex = DexParser::parse(&current).map_err(|error| error.to_string())?;
    }

    let mut source_files_removed = 0_usize;
    let mut debug_info_detached = 0_usize;
    if strip_metadata {
        let (rewritten, report) =
            MetadataReducer::strip_debug_metadata(&dex).map_err(|error| error.to_string())?;
        current = rewritten;
        source_files_removed = report.source_files_removed;
        debug_info_detached = report.debug_info_detached;
    }

    let final_dex = DexParser::parse(&current).map_err(|error| error.to_string())?;
    let _ = DexValidator::validate(&final_dex).map_err(|error| error.to_string())?;
    fs::write(&output, current).map_err(|error| error.to_string())?;

    println!("DEX rewrite: OK");
    println!("Renamed string slots: {renamed}");
    println!("Source-file metadata removed: {source_files_removed}");
    println!("Debug-info links detached: {debug_info_detached}");
    println!("Output: {}", output.display());
    Ok(())
}

fn run_dex_multidex_verify(args: &[String]) -> Result<(), String> {
    if args.is_empty() || args.iter().any(|value| value == "--help" || value == "-h") {
        print_dex_multidex_help();
        return Ok(());
    }

    let mut inputs = Vec::with_capacity(args.len());
    for value in args {
        let path = PathBuf::from(value);
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("invalid DEX filename '{}'", path.display()))?
            .to_owned();
        let bytes = fs::read(&path).map_err(|error| error.to_string())?;
        inputs.push(DexInput { name, bytes });
    }

    let set = MultiDexSet::parse(inputs).map_err(|error| error.to_string())?;
    println!("Multidex set: OK");
    println!("DEX files: {}", set.units.len());
    for unit in set.units {
        println!(
            "  {}: classes={} methods={} strings={}",
            unit.name,
            unit.dex.classes.len(),
            unit.dex.methods.len(),
            unit.dex.strings.len()
        );
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
fn run_protect(args: &[String], phase_a_only: bool) -> Result<(), String> {
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
    let mut plan_only = false;
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
            "--plan-only" => {
                plan_only = true;
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

    if plan_only && phase_a_only {
        return Err("package-apk does not support --plan-only; use protect --plan-only".into());
    }

    if plan_only {
        let context =
            ProductionBuildContext::prepare(&request).map_err(|error| error.to_string())?;
        let dex = context.inspect_dex().map_err(|error| error.to_string())?;
        println!("Phase O.1 production plan: READ-ONLY, NOT PROTECTED");
        println!("Input SHA-256: {}", dex.inspected_input_sha256);
        println!("Profile: {}", context.profile());
        println!("DEX units: {}", dex.units.len());
        println!("Total decoded DEX bytes: {}", dex.total_decoded_bytes);
        for unit in &dex.units {
            println!(
                "  {}: classes={}, methods={}, fields={}, selected={}/{}/{}, reflection={}, native={}, protected-names={}",
                unit.name, unit.class_count, unit.method_count, unit.field_count,
                unit.selected_classes, unit.selected_methods, unit.selected_fields,
                unit.reflection_detected, unit.native_method_count, unit.protected_string_count
            );
        }
        for stage in context.stages() {
            println!(
                "Stage {}: {:?}, {:?}",
                stage.stage.as_str(),
                stage.requirement,
                stage.integration
            );
        }
        let missing = context.required_unintegrated();
        println!("Production ready: false");
        println!("Required stages not integrated: {}", missing.len());
        println!("No APK, signing data or build reports were created.");
        return Ok(());
    }

    let result = if phase_a_only {
        protect_apk(&request)
    } else {
        protect_production_apk(&request)
    }
    .map_err(|error| error.to_string())?;
    println!("Nexora Shield Phase A packaging ONLY — NOT FULL PROTECTION");
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

fn parse_u64(value: &str, option: &str) -> Result<u64, String> {
    let parsed = value
        .strip_prefix("0x")
        .map_or_else(|| value.parse::<u64>(), |hex| u64::from_str_radix(hex, 16));
    parsed.map_err(|_| format!("{option} expects an unsigned integer, got '{value}'"))
}

fn split_member_selector<'a>(value: &'a str, option: &str) -> Result<(&'a str, &'a str), String> {
    let (class_pattern, member_pattern) = value
        .split_once('#')
        .ok_or_else(|| format!("{option} expects <class-glob>#<member-glob>"))?;
    if class_pattern.is_empty() || member_pattern.is_empty() {
        return Err(format!(
            "{option} expects non-empty class and member patterns"
        ));
    }
    Ok((class_pattern, member_pattern))
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
  protect      Production protection (fails closed until all required controls exist)\n\
  package-apk  Legacy Phase A normalization, alignment and signing ONLY\n\
  inspect      Inspect APK structure, manifest and multi-DEX layout\n\
  verify           Verify APK structure and optionally Android signatures\n\
  data-protect     Protect one string/constant/resource/generic data item\n\
  data-unprotect   Authenticate and decrypt a protected data item\n\
  data-inspect     Inspect non-secret protected-container metadata\n\
  data-benchmark   Measure plaintext exposure and protected-size overhead\n\
  data-help        Show Phase C data-protection commands\n\
  integrity-create Build Phase D integrity manifest\n\
  integrity-verify Verify full/distributed integrity evidence\n\
  integrity-inspect Validate and inspect an integrity manifest\n\
  integrity-help   Show Phase D integrity commands\n\
  profiles         List stable protection profiles\n\n\
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
Production protection fails closed while O.1 is unfinished. Use --plan-only for\n\
read-only inspection. package-apk is legacy Phase A packaging ONLY.\n\
Signing and alignment are required unless disabled explicitly.\n\n\
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
  --plan-only                 Read-only O.1 DEX preflight; does NOT protect or write output\n\
  --public-report <file>      Write non-sensitive JSON report\n\
  --private-report <file>     Write private build JSON report"
    );
}

fn print_dex_inspect_help() {
    println!(
        "USAGE:\n  nexora-shield dex-inspect <classes.dex>\n\n\
Parses and validates DEX tables/code, then builds CFG, type analysis, SSA IR, reference graph and compatibility analysis."
    );
}

fn print_dex_roundtrip_help() {
    println!(
        "USAGE:\n  nexora-shield dex-roundtrip <classes.dex> --output <out.dex>\n\n\
Runs the Phase B writer without semantic transforms and validates the result."
    );
}

fn print_dex_rewrite_help() {
    println!(
        "USAGE:\n  nexora-shield dex-rewrite <classes.dex> --output <out.dex> [OPTIONS]\n\n\
OPTIONS:\n\
  --rename                       Enable compatibility-aware fixed-layout renaming\n\
  --strip-metadata               Remove source-file links and detach debug-info data\n\
  --seed <u64|0xhex>             Deterministic rename seed\n\
  --class <class-glob>           Restrict class renames\n\
  --method <class#member>        Restrict method renames\n\
  --field <class#member>         Restrict field renames"
    );
}

fn print_dex_multidex_help() {
    println!(
        "USAGE:\n  nexora-shield dex-multidex-verify <classes.dex> [classes2.dex ...]\n\n\
Validates canonical numbering and every DEX in the set."
    );
}
