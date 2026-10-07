use nexora_shield_release::{
    migrate_to_current, ApiSurface, ArtifactDigest, CompatibilityMatrix, FeedbackStatus,
    QualificationPolicy, ReleaseChannel, ReleaseVersion,
};
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("nexora-shield-release: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_help();
        return Ok(());
    }

    match args.remove(0).as_str() {
        "api-validate" => {
            let path = one_path(&args, "api-validate")?;
            let contract = ApiSurface::load(&path).map_err(|error| error.to_string())?;
            println!(
                "API contract: OK | version={} | schema={} | commands={}",
                contract.contract_version,
                contract.config_schema,
                contract.cli_commands.len()
            );
            Ok(())
        }
        "config-migrate-json" => run_migration(&args),
        "compatibility-validate" => {
            let path = one_path(&args, "compatibility-validate")?;
            CompatibilityMatrix::load(&path).map_err(|error| error.to_string())?;
            println!("Compatibility matrix: OK");
            Ok(())
        }
        "qualification-validate" => {
            let path = one_path(&args, "qualification-validate")?;
            QualificationPolicy::load(&path).map_err(|error| error.to_string())?;
            println!("Release qualification policy: OK");
            Ok(())
        }
        "feedback-validate" => run_feedback(&args),
        "version-check" => run_version_check(&args),
        "artifact-digest" => run_artifact_digest(&args),
        "-h" | "--help" | "help" => {
            print_help();
            Ok(())
        }
        "-V" | "--version" => {
            println!("nexora-shield-release {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        command => Err(format!(
            "unknown command '{command}'. Run 'nexora-shield-release --help'."
        )),
    }
}

fn run_migration(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: nexora-shield-release config-migrate-json <input.json> <output.json>".into(),
        );
    }
    let input = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[1]);
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&input).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let migration = migrate_to_current(document).map_err(|error| error.to_string())?;
    let encoded =
        serde_json::to_vec_pretty(&migration.document).map_err(|error| error.to_string())?;
    output
        .parent()
        .map(std::fs::create_dir_all)
        .transpose()
        .map_err(|error| error.to_string())?;
    std::fs::write(&output, encoded).map_err(|error| error.to_string())?;
    println!(
        "Config migration: OK | {} -> {} | changed={}",
        migration.source_schema, migration.target_schema, migration.changed
    );
    Ok(())
}

fn run_feedback(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: nexora-shield-release feedback-validate <policy.json> <feedback.json>".into(),
        );
    }
    let policy =
        QualificationPolicy::load(&PathBuf::from(&args[0])).map_err(|error| error.to_string())?;
    let feedback =
        FeedbackStatus::load(&PathBuf::from(&args[1])).map_err(|error| error.to_string())?;
    if !policy.stable_feedback_satisfied(&feedback) {
        return Err(format!(
            "stable release blocked: external_reviewers={} required={} blocking_findings_open={}",
            feedback.external_reviewers,
            policy.minimum_external_reviewers,
            feedback.blocking_findings_open
        ));
    }
    println!("External feedback gate: OK");
    Ok(())
}

fn run_version_check(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err("usage: nexora-shield-release version-check <version> <rc|stable>".into());
    }
    let version = ReleaseVersion::parse(&args[0]).map_err(|error| error.to_string())?;
    let channel = match args[1].as_str() {
        "rc" => ReleaseChannel::Rc,
        "stable" => ReleaseChannel::Stable,
        _ => return Err("channel must be rc or stable".into()),
    };
    version
        .require_1_0_channel(channel)
        .map_err(|error| error.to_string())?;
    println!("Release version: OK | {version}");
    Ok(())
}

fn run_artifact_digest(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: nexora-shield-release artifact-digest <file> [file ...]".into());
    }
    let mut digests = Vec::with_capacity(args.len());
    for value in args {
        digests.push(
            ArtifactDigest::from_file(&PathBuf::from(value)).map_err(|error| error.to_string())?,
        );
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&digests).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn one_path(args: &[String], command: &str) -> Result<PathBuf, String> {
    if args.len() != 1 {
        return Err(format!("usage: nexora-shield-release {command} <file>"));
    }
    Ok(PathBuf::from(&args[0]))
}

fn print_help() {
    println!(
        "Nexora Shield Release {}\n\n\
Production-hardening and 1.0 release qualification tooling.\n\n\
COMMANDS:\n\
  api-validate <api-surface.json>\n\
  config-migrate-json <input.json> <output.json>\n\
  compatibility-validate <matrix.json>\n\
  qualification-validate <policy.json>\n\
  feedback-validate <policy.json> <feedback.json>\n\
  version-check <version> <rc|stable>\n\
  artifact-digest <file> [file ...]",
        env!("CARGO_PKG_VERSION")
    );
}
