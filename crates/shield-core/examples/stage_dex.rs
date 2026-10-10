//! Internal Phase O.1 diagnostic only. Never ship this as a release entrypoint.
//! --retrace-map emits a private encrypted sidecar, never a plaintext mapping.
use nexora_shield_core::{ProductionBuildContext, ProtectionProfile, ProtectionRequest};
use nexora_shield_crypto::{BuildIdentity, KeySchedule};
use nexora_shield_dex::{MultiDexRewriteConfig, RenameConfig};
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let input = PathBuf::from(args.next().ok_or("missing APK input")?);
    let staging = PathBuf::from(args.next().ok_or("missing staging destination")?);
    let extra = args.collect::<Vec<_>>();
    let protected = match extra.as_slice() {
        [] => None,
        [flag1, map, flag2, key, flag3, application, flag4, build]
            if flag1 == "--retrace-map"
                && flag2 == "--retrace-key-file"
                && flag3 == "--application-id"
                && flag4 == "--build-id" =>
        {
            Some((
                PathBuf::from(map),
                PathBuf::from(key),
                application.clone(),
                build.clone(),
            ))
        }
        _ => {
            return Err(
                "usage: stage_dex <input.apk> <new-staging.apk> [--retrace-map <new-private-file> --retrace-key-file <existing-32-byte-secret-file> --application-id <id> --build-id <id>]"
                    .into(),
            );
        }
    };
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
    let config = MultiDexRewriteConfig {
        rename: Some(RenameConfig::default()),
        strip_metadata: true,
        conservative_cross_dex_reflection: true,
    };

    let summary = if let Some((map_path, key_path, application_id, build_id)) = protected {
        let schedule = read_private_schedule(&key_path, &application_id, &build_id)?;
        context.stage_dex_rewrite_with_protected_retrace(&staging, &map_path, &config, &schedule)?
    } else {
        context.stage_dex_rewrite(&staging, &config)?
    };
    println!("DEX STAGING ONLY — NOT FULL PROTECTION");
    println!("DEX units: {}", summary.dex_units);
    println!("Changed DEX units: {}", summary.changed_dex_units);
    println!("Renamed strings: {}", summary.name_records);
    println!(
        "Verified unchanged code items: {}",
        summary.verified_code_items
    );
    println!("Removed source files: {}", summary.source_files_removed);
    println!("Staged SHA-256: {}", summary.output_sha256);
    Ok(())
}

fn read_private_schedule(
    secret_path: &Path,
    application_id: &str,
    build_id: &str,
) -> Result<KeySchedule, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::symlink_metadata(secret_path)?;
        if !meta.file_type().is_file() || meta.permissions().mode() & 0o077 != 0 || meta.len() != 32
        {
            return Err("retrace key must be a regular, private 0600, 32-byte file".into());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (secret_path, application_id, build_id);
        return Err("private retrace map output requires Unix secure file handling".into());
    }
    let identity = BuildIdentity::new(application_id, build_id)?;
    let mut root_secret = fs::read(secret_path)?;
    let schedule = KeySchedule::new(&root_secret, identity);
    root_secret.fill(0);
    Ok(schedule?)
}
