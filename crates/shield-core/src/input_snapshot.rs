//! A private, hash-bound input copy used by every multi-read DEX operation.
//! Hashing a mutable path before/after reads alone cannot exclude ABA substitution.

use crate::{CoreError, Result};
use nexora_shield_package::sha256_file;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_SNAPSHOT: AtomicU64 = AtomicU64::new(0);
// The package writer supports ZIP32 only. Bound even concurrently growing input.
const MAX_SNAPSHOT_BYTES: u64 = u32::MAX as u64;

#[derive(Debug)]
pub(crate) struct InputSnapshot {
    directory: PathBuf,
}

impl InputSnapshot {
    pub(crate) fn capture(source: &Path, expected_sha256: &str) -> Result<Self> {
        let mut input = File::open(source)?;
        let metadata = input.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_SNAPSHOT_BYTES {
            return Err(CoreError::InvalidRequest(
                "production input snapshot requires a regular ZIP32-sized file".into(),
            ));
        }
        let snapshot = Self::create_directory()?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(snapshot.path())?;
        let copied = std::io::copy(&mut (&mut input).take(MAX_SNAPSHOT_BYTES + 1), &mut output)?;
        output.sync_all()?;
        drop(output);
        if copied != metadata.len() || sha256_file(&snapshot.path())? != expected_sha256 {
            return Err(CoreError::InvalidRequest(
                "input APK changed while capturing the planned input snapshot".into(),
            ));
        }
        Ok(snapshot)
    }

    fn create_directory() -> Result<Self> {
        for _ in 0..128 {
            let sequence = NEXT_SNAPSHOT.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir()
                .join(format!("nexora-input-{}-{sequence}", std::process::id(),));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&directory) {
                Ok(()) => return Ok(Self { directory }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(CoreError::Transaction(
            "unable to allocate private input snapshot".into(),
        ))
    }

    pub(crate) fn path(&self) -> PathBuf {
        self.directory.join("input.apk")
    }
}

impl Drop for InputSnapshot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[cfg(test)]
mod tests {
    use super::InputSnapshot;
    use nexora_shield_package::sha256_file;
    use std::fs;

    #[test]
    fn snapshot_survives_source_substitution_and_cleans_up(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let source = InputSnapshot::create_directory()?;
        fs::write(source.path(), b"planned APK bytes")?;
        let expected = sha256_file(&source.path())?;
        let snapshot = InputSnapshot::capture(&source.path(), &expected)?;
        fs::write(source.path(), b"replaced APK bytes")?;
        assert_eq!(fs::read(snapshot.path())?, b"planned APK bytes");
        assert!(InputSnapshot::capture(&source.path(), &expected).is_err());
        // Restoring a mutable source does not change the already frozen bytes.
        fs::write(source.path(), b"planned APK bytes")?;
        assert_eq!(sha256_file(&snapshot.path())?, expected);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&snapshot.directory)?.permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(snapshot.path())?.permissions().mode() & 0o777,
                0o600
            );
        }
        let path = snapshot.directory.clone();
        drop(snapshot);
        assert!(!path.exists());
        Ok(())
    }
}
