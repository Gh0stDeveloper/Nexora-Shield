use crate::{runtime_smali::refuse, Result};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
#[derive(Debug)]
pub(super) struct Workspace {
    pub path: PathBuf,
    preserve: bool,
}
impl Workspace {
    pub fn create(parent: &Path) -> Result<Self> {
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        fs::create_dir_all(parent)?;
        let parent = fs::canonicalize(parent)?;
        for _ in 0..128 {
            let path = parent.join(format!(
                ".nexora-o1-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        preserve: false,
                    })
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(refuse(
            "unable to allocate integrated transaction workspace",
        ))
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        if !self.preserve {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
pub(super) fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
type Prepared<'a> = (Workspace, &'a Path, bool, bool, bool);
pub(super) fn publish(files: &[(&Path, &Path)], overwrite: bool) -> Result<()> {
    commit(prepare(files, overwrite)?)
}
fn prepare<'a>(files: &[(&Path, &'a Path)], overwrite: bool) -> Result<Vec<Prepared<'a>>> {
    let mut prepared = Vec::new();
    for (source, target) in files {
        let w = Workspace::create(
            target
                .parent()
                .ok_or_else(|| refuse("invalid publication destination"))?,
        )?;
        let pending = w.path.join("pending");
        fs::copy(source, &pending)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&pending, fs::Permissions::from_mode(0o600))?;
        }
        fs::File::open(&pending)?.sync_all()?;
        let exists = match fs::symlink_metadata(target) {
            Ok(m) if m.is_file() && overwrite => true,
            Ok(_) => {
                return Err(refuse(
                    "publication destination exists or is not a regular file",
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        prepared.push((w, *target, exists, false, false));
    }
    Ok(prepared)
}
fn commit(mut prepared: Vec<Prepared<'_>>) -> Result<()> {
    for i in 0..prepared.len() {
        let (w, target, exists, backed, published) = &mut prepared[i];
        let result = (|| {
            if *exists {
                fs::rename(*target, w.path.join("backup"))?;
                *backed = true;
            }
            fs::hard_link(w.path.join("pending"), *target)?;
            *published = true;
            Ok(())
        })();
        if let Err(e) = result {
            rollback(&mut prepared)?;
            return Err(e);
        }
    }
    Ok(())
}
fn rollback(prepared: &mut [Prepared<'_>]) -> Result<()> {
    let mut retained = Vec::new();
    for (w, target, _, backed, published) in prepared.iter_mut().rev() {
        let result = (|| {
            if *published {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    let a = fs::symlink_metadata(*target)?;
                    let b = fs::metadata(w.path.join("pending"))?;
                    if a.dev() != b.dev() || a.ino() != b.ino() {
                        return Err(refuse("published output was replaced concurrently"));
                    }
                }
                fs::remove_file(*target)?;
            }
            if *backed {
                fs::hard_link(w.path.join("backup"), *target)?;
            }
            Ok(())
        })();
        if let Err(_e) = result {
            w.preserve = true;
            retained.push(w.path.display().to_string());
        }
    }
    if retained.is_empty() {
        Ok(())
    } else {
        Err(crate::CoreError::Transaction(format!(
            "publication rollback needs recovery; private backups retained at {}",
            retained.join(", ")
        )))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn group_publication_refuses_conflicts_before_replacing_anything() -> Result<()> {
        let w = Workspace::create(&std::env::temp_dir())?;
        let source = w.path.join("source");
        private_write(&source, b"new")?;
        let a = w.path.join("a");
        let b = w.path.join("b");
        private_write(&a, b"old")?;
        fs::create_dir(&b)?;
        assert!(publish(&[(&source, &a), (&source, &b)], true).is_err());
        assert_eq!(fs::read(&a)?, b"old");
        fs::remove_dir(&b)?;
        publish(&[(&source, &a), (&source, &b)], true)?;
        assert_eq!(fs::read(&a)?, b"new");
        assert_eq!(fs::read(&b)?, b"new");
        assert!(publish(&[(&source, &a)], false).is_err());
        Ok(())
    }
    #[test]
    fn late_collision_restores_old_output_and_preserves_foreign_file() -> Result<()> {
        let w = Workspace::create(&std::env::temp_dir())?;
        let source = w.path.join("source");
        private_write(&source, b"new")?;
        let a = w.path.join("a");
        let b = w.path.join("b");
        private_write(&a, b"old")?;
        let prepared = prepare(&[(&source, &a), (&source, &b)], true)?;
        private_write(&b, b"concurrent writer")?;
        assert!(commit(prepared).is_err());
        assert_eq!(fs::read(&a)?, b"old");
        assert_eq!(fs::read(&b)?, b"concurrent writer");
        Ok(())
    }
}
