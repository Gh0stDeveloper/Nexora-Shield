//! Qualification-only authenticated VM evidence; no original instructions/values are printed.
use nexora_shield_native::{RuntimeEntryKind, RuntimeImage};
use std::{fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut reports = Vec::new();
    for path in std::env::args().skip(1) {
        let image = read_image(Path::new(&path))?;
        let mut methods = Vec::new();
        for entry in image
            .entries
            .iter()
            .filter(|e| e.kind == RuntimeEntryKind::IntVm)
        {
            let evidence = image.int_vm_evidence(entry.slot)?;
            methods.push(serde_json::json!({"slot":entry.slot,"instruction_count":evidence.instruction_count,"opcode_map_sha256":evidence.opcode_map_sha256,"opcode_stream_sha256":evidence.opcode_stream_sha256,"cfg_sha256":evidence.cfg_sha256}));
        }
        reports.push(methods);
    }
    if reports.is_empty() {
        return Err("private runtime image required".into());
    }
    println!("{}", serde_json::to_string(&reports)?);
    Ok(())
}
fn read_image(path: &Path) -> Result<RuntimeImage, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > 32 * 1024 * 1024 {
        return Err("invalid private runtime image".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("runtime image must be private".into());
        }
    }
    let bytes = zeroize::Zeroizing::new(fs::read(path)?);
    let image: RuntimeImage = serde_json::from_slice(&bytes)?;
    image.authenticate()?;
    Ok(image)
}
