use nexora_shield_crypto::{
    inspect_container, open, seal, BuildIdentity, ContainerKind, ExposureBenchmark, ExposureProbe,
    KeySchedule, ROOT_SECRET_LEN,
};
use std::fs;
use std::path::PathBuf;

pub(crate) fn run_data_protect(args: &[String]) -> Result<(), String> {
    if args.is_empty() || wants_help(args) {
        print_data_protect_help();
        return Ok(());
    }

    let input = PathBuf::from(&args[0]);
    let options = parse_crypto_options(&args[1..], true)?;
    let schedule = load_schedule(&options)?;
    let output = options
        .output
        .ok_or_else(|| "data-protect requires --output <file>".to_owned())?;
    let kind = options.kind.ok_or_else(|| {
        "data-protect requires --kind <string|constant|resource|generic>".to_owned()
    })?;
    let logical_id = options
        .logical_id
        .as_deref()
        .ok_or_else(|| "data-protect requires --id <logical-id>".to_owned())?;
    let plaintext = fs::read(&input).map_err(|error| error.to_string())?;
    let protected =
        seal(&schedule, kind, logical_id, &plaintext).map_err(|error| error.to_string())?;
    fs::write(&output, &protected).map_err(|error| error.to_string())?;
    let info = inspect_container(&protected).map_err(|error| error.to_string())?;

    println!("Data protection: OK");
    println!("Input bytes: {}", plaintext.len());
    println!("Protected bytes: {}", protected.len());
    println!("Kind: {:?}", info.kind);
    println!("Output: {}", output.display());
    Ok(())
}

pub(crate) fn run_data_unprotect(args: &[String]) -> Result<(), String> {
    if args.is_empty() || wants_help(args) {
        print_data_unprotect_help();
        return Ok(());
    }

    let input = PathBuf::from(&args[0]);
    let options = parse_crypto_options(&args[1..], true)?;
    let schedule = load_schedule(&options)?;
    let output = options
        .output
        .ok_or_else(|| "data-unprotect requires --output <file>".to_owned())?;
    let kind = options.kind.ok_or_else(|| {
        "data-unprotect requires --kind <string|constant|resource|generic>".to_owned()
    })?;
    let logical_id = options
        .logical_id
        .as_deref()
        .ok_or_else(|| "data-unprotect requires --id <logical-id>".to_owned())?;
    let protected = fs::read(&input).map_err(|error| error.to_string())?;
    let plaintext =
        open(&schedule, kind, logical_id, &protected).map_err(|error| error.to_string())?;
    fs::write(&output, &plaintext).map_err(|error| error.to_string())?;

    println!("Data decryption: OK");
    println!("Recovered bytes: {}", plaintext.len());
    println!("Output: {}", output.display());
    Ok(())
}

pub(crate) fn run_data_inspect(args: &[String]) -> Result<(), String> {
    if args.len() != 1 || wants_help(args) {
        print_data_inspect_help();
        return Ok(());
    }
    let input = PathBuf::from(&args[0]);
    let bytes = fs::read(&input).map_err(|error| error.to_string())?;
    let info = inspect_container(&bytes).map_err(|error| error.to_string())?;

    println!("Container: {}", input.display());
    println!("Version: {}", info.version);
    println!("Kind: {:?}", info.kind);
    println!("Plaintext bytes: {}", info.plaintext_len);
    println!("Ciphertext bytes: {}", info.ciphertext_len);
    println!(
        "Opaque ID: {}",
        nexora_shield_crypto::hex_lower(&info.item_id)
    );
    Ok(())
}

pub(crate) fn run_data_benchmark(args: &[String]) -> Result<(), String> {
    if args.len() < 2 || wants_help(args) {
        print_data_benchmark_help();
        return Ok(());
    }

    let baseline = fs::read(&args[0]).map_err(|error| error.to_string())?;
    let protected = fs::read(&args[1]).map_err(|error| error.to_string())?;
    let mut probe_env = None;
    let mut label = "critical-probe".to_owned();
    let mut maximum_overhead = 10.0_f64;

    let mut index = 2_usize;
    while index < args.len() {
        match args[index].as_str() {
            "--probe-env" => {
                probe_env = Some(require_value(args, index, "--probe-env")?.to_owned());
                index += 2;
            }
            "--label" => {
                label = require_value(args, index, "--label")?.to_owned();
                index += 2;
            }
            "--max-overhead" => {
                maximum_overhead = require_value(args, index, "--max-overhead")?
                    .parse::<f64>()
                    .map_err(|_| "--max-overhead expects a number".to_owned())?;
                if !maximum_overhead.is_finite() || maximum_overhead < 0.0 {
                    return Err("--max-overhead must be a finite non-negative number".into());
                }
                index += 2;
            }
            option => return Err(format!("unknown data-benchmark option '{option}'")),
        }
    }

    let env_name =
        probe_env.ok_or_else(|| "data-benchmark requires --probe-env <ENV>".to_owned())?;
    let probe = std::env::var(&env_name)
        .map_err(|_| format!("required probe environment variable '{env_name}' is not set"))?;
    let report = ExposureBenchmark::run(
        &baseline,
        &protected,
        &[ExposureProbe::new(label, probe.into_bytes(), true)
            .map_err(|error| error.to_string())?],
    )
    .map_err(|error| error.to_string())?;

    println!("Exposure benchmark");
    println!("Baseline bytes: {}", report.baseline_bytes);
    println!("Protected bytes: {}", report.protected_bytes);
    println!("Overhead: {:.3}%", report.overhead_percent);
    println!("Critical probes exposed: {}", report.critical_exposed);
    println!(
        "Budget result: {}",
        if report.passes(maximum_overhead) {
            "PASS"
        } else {
            "FAIL"
        }
    );

    if !report.passes(maximum_overhead) {
        return Err("data-protection exposure/overhead budget failed".into());
    }
    Ok(())
}

#[derive(Debug, Default)]
struct CryptoOptions {
    output: Option<PathBuf>,
    kind: Option<ContainerKind>,
    logical_id: Option<String>,
    application_id: Option<String>,
    build_id: Option<String>,
    key_env: Option<String>,
}

fn parse_crypto_options(args: &[String], require_output: bool) -> Result<CryptoOptions, String> {
    let mut options = CryptoOptions::default();
    let mut index = 0_usize;

    while index < args.len() {
        match args[index].as_str() {
            "-o" | "--output" if require_output => {
                options.output = Some(PathBuf::from(require_value(args, index, "--output")?));
                index += 2;
            }
            "--kind" => {
                options.kind = Some(parse_kind(require_value(args, index, "--kind")?)?);
                index += 2;
            }
            "--id" => {
                options.logical_id = Some(require_value(args, index, "--id")?.to_owned());
                index += 2;
            }
            "--app-id" => {
                options.application_id = Some(require_value(args, index, "--app-id")?.to_owned());
                index += 2;
            }
            "--build-id" => {
                options.build_id = Some(require_value(args, index, "--build-id")?.to_owned());
                index += 2;
            }
            "--key-env" => {
                options.key_env = Some(require_value(args, index, "--key-env")?.to_owned());
                index += 2;
            }
            option => return Err(format!("unknown data-protection option '{option}'")),
        }
    }

    Ok(options)
}

fn load_schedule(options: &CryptoOptions) -> Result<KeySchedule, String> {
    let application_id = options
        .application_id
        .as_deref()
        .ok_or_else(|| "missing --app-id <application-id>".to_owned())?;
    let build_id = options
        .build_id
        .as_deref()
        .ok_or_else(|| "missing --build-id <build-id>".to_owned())?;
    let key_env = options
        .key_env
        .as_deref()
        .ok_or_else(|| "missing --key-env <ENV>".to_owned())?;
    let encoded = std::env::var(key_env)
        .map_err(|_| format!("required key environment variable '{key_env}' is not set"))?;
    let root = decode_hex_32(encoded.trim())?;
    let identity =
        BuildIdentity::new(application_id, build_id).map_err(|error| error.to_string())?;
    KeySchedule::new(&root, identity).map_err(|error| error.to_string())
}

fn decode_hex_32(value: &str) -> Result<[u8; ROOT_SECRET_LEN], String> {
    if value.len() != ROOT_SECRET_LEN * 2 {
        return Err(format!(
            "data-protection root key must be {} hexadecimal characters",
            ROOT_SECRET_LEN * 2
        ));
    }

    let mut output = [0_u8; ROOT_SECRET_LEN];
    for (index, slot) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| "data-protection root key is not valid hexadecimal".to_owned())?;
    }
    Ok(output)
}

fn parse_kind(value: &str) -> Result<ContainerKind, String> {
    match value {
        "string" => Ok(ContainerKind::String),
        "constant" => Ok(ContainerKind::Constant),
        "resource" => Ok(ContainerKind::Resource),
        "generic" => Ok(ContainerKind::Generic),
        other => Err(format!("unknown data container kind '{other}'")),
    }
}

fn wants_help(args: &[String]) -> bool {
    args.iter().any(|value| value == "--help" || value == "-h")
}

fn require_value<'a>(args: &'a [String], index: usize, option: &str) -> Result<&'a str, String> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("{option} requires a value"))
}

pub(crate) fn print_data_help() {
    println!(
        "Phase C data-protection commands:\n\
  data-protect     Authenticated encryption for one data item\n\
  data-unprotect   Decrypt and authenticate one protected item\n\
  data-inspect     Inspect non-secret container metadata\n\
  data-benchmark   Check plaintext exposure and size overhead"
    );
}

fn print_data_protect_help() {
    println!(
        "USAGE:\n  nexora-shield data-protect <input> --output <container> \\\n\
    --kind <string|constant|resource|generic> --id <logical-id> \\\n\
    --app-id <application-id> --build-id <build-id> --key-env <ENV>\n\n\
The 32-byte root secret is read as 64 hex characters from ENV and is never accepted on the command line."
    );
}

fn print_data_unprotect_help() {
    println!(
        "USAGE:\n  nexora-shield data-unprotect <container> --output <file> \\\n\
    --kind <string|constant|resource|generic> --id <logical-id> \\\n\
    --app-id <application-id> --build-id <build-id> --key-env <ENV>"
    );
}

fn print_data_inspect_help() {
    println!("USAGE:\n  nexora-shield data-inspect <container>");
}

fn print_data_benchmark_help() {
    println!(
        "USAGE:\n  nexora-shield data-benchmark <baseline> <protected> \\\n\
    --probe-env <ENV> [--label <name>] [--max-overhead <percent>]\n\n\
The sensitive probe value is read from an environment variable so it does not appear in argv."
    );
}
