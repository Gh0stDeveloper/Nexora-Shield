//! Internal Phase O.1 diagnostic only. Never ship this as a release entrypoint.
use nexora_shield_core::{ProductionBuildContext, ProtectionProfile, ProtectionRequest};
use nexora_shield_dex::{MultiDexRewriteConfig, RenameConfig};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let input = PathBuf::from(args.next().ok_or("missing APK input")?);
    let staging = PathBuf::from(args.next().ok_or("missing staging destination")?);
    if args.next().is_some() {
        return Err("usage: stage_dex <input.apk> <new-staging.apk>".into());
    }
    let proposed_production_output = staging.with_extension("not-a-production-output");
    let context = ProductionBuildContext::prepare(&ProtectionRequest {
        input,
        output: proposed_production_output,
        profile: ProtectionProfile::Standard,
        align: false,
        allow_unsigned: true,
        overwrite: false,
        signing: None,
        zipalign: None,
        apksigner: None,
        public_report: None,
        private_report: None,
    })?;
    let summary = context.stage_dex_rewrite(
        &staging,
        &MultiDexRewriteConfig {
            rename: Some(RenameConfig::default()),
            strip_metadata: true,
            conservative_cross_dex_reflection: true,
        },
    )?;
    println!("DEX STAGING ONLY — NOT FULL PROTECTION");
    println!("DEX units: {}", summary.dex_units);
    println!("Changed DEX units: {}", summary.changed_dex_units);
    println!("Renamed strings: {}", summary.name_records);
    println!("Verified unchanged code items: {}", summary.verified_code_items);
    println!("Removed source files: {}", summary.source_files_removed);
    println!("Staged SHA-256: {}", summary.output_sha256);
    Ok(())
}
