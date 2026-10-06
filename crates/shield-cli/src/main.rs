//! Nexora Shield command-line entry point.

#![forbid(unsafe_code)]

use nexora_shield_core::{ProtectionProfile, CONFIG_SCHEMA_VERSION};

fn main() {
    let mut args = std::env::args();
    let _binary = args.next();

    match args.next().as_deref() {
        None | Some("--help" | "-h") => print_help(),
        Some("--version" | "-V") => println!("nexora-shield {}", env!("CARGO_PKG_VERSION")),
        Some("profiles") => print_profiles(),
        Some(command) => {
            eprintln!(
                "unknown command '{command}'. Phase 0 exposes only metadata commands;                  protection commands arrive in Phase A."
            );
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!(
        "Nexora Shield {}\n\n         Android application protection and RASP platform.\n\n         USAGE:\n  nexora-shield [COMMAND]\n\n         COMMANDS:\n  profiles     List stable protection profiles\n\n         OPTIONS:\n  -h, --help       Print help\n  -V, --version    Print version\n\n         Configuration schema: {}",
        env!("CARGO_PKG_VERSION"),
        CONFIG_SCHEMA_VERSION
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
