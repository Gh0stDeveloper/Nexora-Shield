use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=NEXORA_RUNTIME_IMAGE");
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing build output")?)
        .join("runtime_image.rs");
    let Some(path) = env::var_os("NEXORA_RUNTIME_IMAGE") else {
        fs::write(output, "pub fn image() -> Option<crate::RuntimeImage> { None }\npub const COMMITMENT: &str = \"UNCONFIGURED\";\n")?;
        return Ok(());
    };
    let path = PathBuf::from(path);
    println!("cargo:rerun-if-changed={}", path.display());
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file() || metadata.len() > 32 * 1024 * 1024 {
        return Err("invalid private runtime configuration file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("runtime configuration must be private".into());
        }
    }
    let bytes = fs::read(path)?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| "invalid runtime configuration")?;
    if value["schema"] != 1 {
        return Err("unsupported runtime configuration schema".into());
    }
    let canonical = serde_json::to_vec(&serde_json::json!([
        value["schema"],
        value["application_id"],
        value["build_id"],
        value["entries"],
        value["guard_key"],
        value["guard_binding"]
    ]))?;
    let digest = Sha256::digest(&canonical);
    let mut fingerprint = String::with_capacity(64);
    for byte in digest {
        write!(fingerprint, "{byte:02x}")?;
    }
    let app = value["application_id"]
        .as_str()
        .ok_or("missing runtime application identity")?;
    let build = value["build_id"]
        .as_str()
        .ok_or("missing runtime build identity")?;
    let left = array(&value["key_share_a"])?;
    let right = array(&value["key_share_b"])?;
    let guard_key = optional_array(&value["guard_key"])?;
    let guard_binding = optional_array(&value["guard_binding"])?;
    if left.len() != 32 || right.len() != 32 {
        return Err("invalid runtime key shares".into());
    }
    let entries = value["entries"]
        .as_array()
        .ok_or("missing runtime inventory")?;
    if entries.is_empty() || entries.len() > 1024 {
        return Err("invalid runtime inventory size".into());
    }
    let mut source = format!("pub const COMMITMENT: &str = \"NEXORA_RUNTIME_V1:{fingerprint}\";\npub fn image() -> Option<crate::RuntimeImage> {{ Some(crate::RuntimeImage {{ schema: 1, application_id: {app:?}.into(), build_id: {build:?}.into(), key_share_a: {left:?}, key_share_b: {right:?}, entries: vec![");
    for entry in entries {
        let slot = entry["slot"]
            .as_u64()
            .filter(|slot| u32::try_from(*slot).is_ok())
            .ok_or("invalid runtime slot")?;
        let kind = match entry["kind"].as_str() {
            Some("String") => "String",
            Some("IntVm") => "IntVm",
            Some("Constant") => "Constant",
            Some("Resource") => "Resource",
            _ => return Err("unsupported runtime entry kind".into()),
        };
        let cipher = array(&entry["ciphertext"])?;
        if cipher.len() > 1024 * 1024 {
            return Err("runtime entry exceeds size limit".into());
        }
        let binary_name = format!("runtime-{slot}.bin");
        fs::write(
            output
                .parent()
                .ok_or("invalid build output")?
                .join(&binary_name),
            &cipher,
        )?;
        write!(source,"crate::RuntimeEntry {{ slot: {slot}, kind: crate::RuntimeEntryKind::{kind}, ciphertext: std::hint::black_box(include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{binary_name}\"))).to_vec() }},")?;
    }
    writeln!(
        source,
        "] , guard_key: {guard_key}, guard_binding: {guard_binding} }}) }}"
    )?;
    fs::write(output, source)?;
    Ok(())
}

fn array(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    value
        .as_array()
        .ok_or_else(|| "invalid runtime byte array".into())
        .and_then(|values| {
            values
                .iter()
                .map(|value| {
                    value
                        .as_u64()
                        .and_then(|v| u8::try_from(v).ok())
                        .ok_or_else(|| "invalid runtime byte value".into())
                })
                .collect()
        })
}

fn optional_array(value: &Value) -> Result<String, Box<dyn std::error::Error>> {
    if value.is_null() {
        return Ok("None".to_owned());
    }
    let bytes = array(value)?;
    if bytes.len() != 32 {
        return Err("invalid guard public binding".into());
    }
    Ok(format!("Some({bytes:?})"))
}
