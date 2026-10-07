use nexora_shield_lab::{
    ExposureRule, RegressionCorpus, RegressionCoverage, StaticExposureHarness,
};
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("nexora-shield-lab: {error}");
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
        "-h" | "--help" | "help" => {
            print_help();
            Ok(())
        }
        "-V" | "--version" => {
            println!("nexora-shield-lab {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "corpus-validate" => run_corpus_validate(&args),
        "coverage-validate" => run_coverage_validate(&args),
        "static-scan" => run_static_scan(&args),
        command => Err(format!(
            "unknown command '{command}'. Run 'nexora-shield-lab --help'."
        )),
    }
}

fn run_corpus_validate(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: nexora-shield-lab corpus-validate <index.json>".into());
    }
    let path = PathBuf::from(&args[0]);
    let corpus = RegressionCorpus::load(&path).map_err(|error| error.to_string())?;
    let fingerprint = corpus.fingerprint().map_err(|error| error.to_string())?;
    println!("Security Lab corpus: OK");
    println!("Cases: {}", corpus.cases.len());
    println!("Fingerprint: {}", hex_lower(&fingerprint));
    Ok(())
}

fn run_coverage_validate(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: nexora-shield-lab coverage-validate <index.json> <coverage.json>".into(),
        );
    }
    let corpus =
        RegressionCorpus::load(&PathBuf::from(&args[0])).map_err(|error| error.to_string())?;
    let coverage =
        RegressionCoverage::load(&PathBuf::from(&args[1])).map_err(|error| error.to_string())?;
    coverage
        .validate_against(&corpus)
        .map_err(|error| error.to_string())?;
    println!("Security Lab corpus coverage: OK");
    println!("Covered cases: {}", coverage.entries.len());
    Ok(())
}

fn run_static_scan(args: &[String]) -> Result<(), String> {
    if args.len() != 7 || args[1] != "--needle-env" || args[3] != "--id" || args[5] != "--max" {
        return Err(
            "usage: nexora-shield-lab static-scan <artifact> --needle-env <VAR> --id <RULE> --max <N>"
                .into(),
        );
    }

    let path = PathBuf::from(&args[0]);
    let needle = std::env::var(&args[2])
        .map_err(|_| format!("environment variable '{}' is not set", args[2]))?;
    let maximum_occurrences = args[6]
        .parse::<usize>()
        .map_err(|_| "--max must be an unsigned integer".to_owned())?;
    let bytes = std::fs::read(&path).map_err(|error| error.to_string())?;
    let report = StaticExposureHarness::scan(
        path.display().to_string(),
        &bytes,
        &[ExposureRule {
            id: args[4].clone(),
            needle,
            maximum_occurrences,
        }],
    )
    .map_err(|error| error.to_string())?;

    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
    );
    if !report.passed() {
        return Err("static exposure budget failed".into());
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn print_help() {
    println!(
        "Nexora Shield Security Lab {}\n\n\
USAGE:\n  nexora-shield-lab <COMMAND> [OPTIONS]\n\n\
COMMANDS:\n\
  corpus-validate <index.json>\n\
      Validate the versioned Security Lab regression corpus.\n\
  coverage-validate <index.json> <coverage.json>\n\
      Require every corpus case to map to an executed release gate.\n\
  static-scan <artifact> --needle-env <VAR> --id <RULE> --max <N>\n\
      Scan an owned/test artifact for a synthetic exposure marker without echoing the marker.\n\n\
This tool is for authorized defensive testing of Nexora Shield and owned test applications.",
        env!("CARGO_PKG_VERSION")
    );
}
