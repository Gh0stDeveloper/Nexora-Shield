//! Explicit, local and authorized retrieval of a private encrypted retrace map.
//! Never run this example in CI with --lookup: that would disclose old names.
use nexora_shield_crypto::{open_retrace_map, BuildIdentity, KeySchedule, MAX_RETRACE_PLAINTEXT};
use nexora_shield_package::verify_apk_structure;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let apk = PathBuf::from(args.next().ok_or("missing staged APK path")?);
    let protected_path = PathBuf::from(args.next().ok_or("missing encrypted retrace file")?);
    let key_path = PathBuf::from(args.next().ok_or("missing private key file")?);
    let application_id = args.next().ok_or("missing application ID")?;
    let build_id = args.next().ok_or("missing build ID")?;
    let more = args.collect::<Vec<_>>();
    let lookup = match more.as_slice() {
        [] => None,
        [flag, dex, obfuscated] if flag == "--lookup" => {
            Some((dex.as_str(), obfuscated.as_str()))
        }
        _ => return Err("usage: retrace_inspect <staged.apk> <encrypted.map> <key-file> <application-id> <build-id> [--lookup <classes.dex> <obfuscated-name>]".into()),
    };

    let key_info = fs::symlink_metadata(&key_path)?;
    let map_info = fs::symlink_metadata(&protected_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !key_info.file_type().is_file()
            || !map_info.file_type().is_file()
            || key_info.permissions().mode() & 0o077 != 0
            || map_info.permissions().mode() & 0o077 != 0
            || key_info.len() != 32
        {
            return Err("retrace key and encrypted sidecar must be private regular files".into());
        }
    }
    #[cfg(not(unix))]
    return Err("private retrace inspection requires Unix secure file handling".into());

    if map_info.len() > (MAX_RETRACE_PLAINTEXT + 128) as u64 {
        return Err("encrypted retrace sidecar exceeds expected size".into());
    }
    let mut root = fs::read(&key_path)?;
    let schedule = KeySchedule::new(&root, BuildIdentity::new(application_id, build_id)?);
    root.fill(0);
    let schedule = schedule?;

    let apk_hash = verify_apk_structure(&apk)?.sha256;
    let protected = fs::read(&protected_path)?;
    let restored = open_retrace_map(&schedule, &apk_hash, &protected)?;
    println!("Private retrace map authenticated for APK: {apk_hash}");
    println!("Retrace records: {}", restored.records.len());
    if let Some((dex, name)) = lookup {
        let matches = restored.candidates(dex, name);
        println!("Matching candidates: {}", matches.len());
        for record in matches {
            // Only an explicit --lookup request may disclose old names.
            println!("{} string[{}]: {}", record.dex_name, record.string_idx, record.original);
        }
    }
    Ok(())
}
