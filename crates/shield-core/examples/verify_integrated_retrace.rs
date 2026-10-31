//! Verify a private retrace map against the exact signed APK.
use nexora_shield_crypto::{open_retrace_map, BuildIdentity, KeySchedule};
use nexora_shield_package::sha256_file;
use std::{fs, path::Path};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a = std::env::args().skip(1).collect::<Vec<_>>();
    if a.len() != 4 {
        return Err(
            "usage: verify_integrated_retrace <report> <map> <private-key> <final-apk>".into(),
        );
    }
    let r: serde_json::Value = serde_json::from_slice(&fs::read(&a[0])?)?;
    let b = zeroize::Zeroizing::new(fs::read(&a[2])?);
    let root: &[u8; 32] = b.as_slice().try_into()?;
    let identity = BuildIdentity::new(
        r["application_id"]
            .as_str()
            .ok_or("missing application identity")?,
        r["runtime_build_id"]
            .as_str()
            .ok_or("missing runtime identity")?,
    )?;
    let schedule = KeySchedule::new(root, identity)?;
    let hash = sha256_file(Path::new(&a[3]))?;
    let map = open_retrace_map(&schedule, &hash, &fs::read(&a[1])?)?;
    if map.apk_sha256 != hash || r["output_sha256"] != hash || map.records.is_empty() {
        return Err("retrace is not bound to final signed APK".into());
    }
    println!("FINAL_APK_RETRACE_VERIFIED records={}", map.records.len());
    Ok(())
}
