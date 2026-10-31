//! Private, bounded inputs for the shared experimental O.1 engine.
use crate::{
    runtime_smali::refuse, DexSelectorPolicy, ProductionControl, ProductionOverrides, Result,
};
use nexora_shield_dex::{Selector, SelectorKind};
use nexora_shield_diversity::{DiversityMode, PrivateBuildSeed};
use serde::Deserialize;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::{fs, io::Read};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IntegratedConfig {
    pub schema: u32,
    pub application_id: String,
    pub build_id: String,
    pub controls: Vec<String>,
    pub runtime_methods: Vec<String>,
    pub assets: Vec<String>,
    pub root_key_file: PathBuf,
    pub diversity_file: PathBuf,
    pub graph_key_file: PathBuf,
    pub signer_sha256: String,
    pub rasp_mode: String,
    pub dex: DexConfig,
    pub tools: BuildTools,
    pub retrace_key_file: Option<PathBuf>,
    pub retrace_output: Option<PathBuf>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DexConfig {
    pub rename: bool,
    pub strip_metadata: bool,
    pub selectors: Vec<SelectionRule>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SelectionRule {
    pub kind: String,
    pub class: String,
    pub member: Option<String>,
    #[serde(default)]
    pub exclude: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BuildTools {
    pub java: PathBuf,
    pub smali_directory: PathBuf,
    pub cargo: PathBuf,
    pub rustc: PathBuf,
    pub native_source: PathBuf,
    pub ndk_directory: PathBuf,
    pub native_cache: PathBuf,
}
impl IntegratedConfig {
    pub fn load(path: &Path) -> Result<Self> {
        if path.extension().and_then(|v| v.to_str()) != Some("nshield-private") {
            return Err(refuse(
                "integrated configuration requires .nshield-private suffix",
            ));
        }
        let bytes = read_private(path, 64 * 1024)?;
        let config: Self = serde_json::from_slice(&bytes).map_err(|_| {
            refuse("invalid integrated configuration (unknown fields are forbidden)")
        })?;
        if config.schema != 1
            || config.runtime_methods.is_empty()
            || config.runtime_methods.len() > 128
            || config.controls.len() > 7
            || config.assets.len() > 768
            || config.dex.selectors.is_empty()
            || config.dex.selectors.len() > 128
            || (!config.dex.rename && !config.dex.strip_metadata)
            || config.dex.rename != config.retrace_key_file.is_some()
            || config.dex.rename != config.retrace_output.is_some()
        {
            return Err(refuse("incomplete or unsupported integrated configuration"));
        }
        for p in config
            .input_paths()
            .into_iter()
            .chain(config.retrace_output.iter())
        {
            if !p.is_absolute() {
                return Err(refuse("integrated paths must be absolute"));
            }
        }
        Ok(config)
    }
    pub fn input_paths(&self) -> Vec<&PathBuf> {
        let mut p = vec![
            &self.root_key_file,
            &self.diversity_file,
            &self.graph_key_file,
            &self.tools.java,
            &self.tools.smali_directory,
            &self.tools.cargo,
            &self.tools.rustc,
            &self.tools.native_source,
            &self.tools.ndk_directory,
            &self.tools.native_cache,
        ];
        p.extend(self.retrace_key_file.iter());
        p
    }
    pub fn overrides(&self) -> Result<ProductionOverrides> {
        let mut o = ProductionOverrides::default();
        for name in &self.controls {
            o.set(name.parse::<ProductionControl>()?, true)?;
        }
        Ok(o)
    }
    pub fn dex_policy(&self) -> Result<DexSelectorPolicy> {
        let mut p = DexSelectorPolicy::default();
        for r in &self.dex.selectors {
            let kind = match r.kind.as_str() {
                "class" if r.member.is_none() => SelectorKind::Class,
                "method" => SelectorKind::Method,
                "field" => SelectorKind::Field,
                _ => return Err(refuse("invalid integrated DEX selector kind")),
            };
            let s = Selector::new(kind, &r.class, r.member.clone())
                .map_err(|_| refuse("invalid integrated DEX selector"))?;
            if r.exclude {
                p.add_exclude(s)?;
            } else {
                p.add_include(s)?;
            }
        }
        if p.includes().is_empty() {
            return Err(refuse("explicit positive DEX selection required"));
        }
        Ok(p)
    }
    pub fn runtime_policy(&self) -> Result<DexSelectorPolicy> {
        let mut p = DexSelectorPolicy::default();
        for value in &self.runtime_methods {
            let (class, member) = value
                .split_once('#')
                .ok_or_else(|| refuse("invalid runtime method selector"))?;
            p.add_include(
                Selector::new(SelectorKind::Method, class, Some(member.into()))
                    .map_err(|_| refuse("invalid runtime method selector"))?,
            )?;
        }
        Ok(p)
    }
}
pub(super) fn read_private(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(not(unix))]
    {
        let _ = (path, limit);
        Err(refuse(
            "integrated private files require Unix permission enforcement",
        ))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let before = fs::symlink_metadata(path)?;
        let file = fs::File::open(path)?;
        let actual = file.metadata()?;
        if !before.is_file()
            || !actual.is_file()
            || before.dev() != actual.dev()
            || before.ino() != actual.ino()
            || actual.len() > limit
            || actual.permissions().mode() & 0o077 != 0
        {
            return Err(refuse(
                "private input must be a bounded, private regular file",
            ));
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(limit + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != actual.len() {
            return Err(refuse("private input changed during capture"));
        }
        Ok(bytes)
    }
}
pub(super) fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = read_private(path, 32)?;
    Ok(Zeroizing::new(bytes.as_slice().try_into().map_err(
        |_| refuse("private key must contain exactly 32 bytes"),
    )?))
}
pub(super) fn read_diversity(path: &Path) -> Result<(PrivateBuildSeed, DiversityMode)> {
    if path.extension().and_then(|v| v.to_str()) != Some("nshield-private") {
        return Err(refuse(
            "private diversity input requires .nshield-private suffix",
        ));
    }
    let b = read_private(path, 295)?;
    if b.len() < 40 || &b[..6] != b"NSDV1\0" {
        return Err(refuse("invalid private diversity format"));
    }
    let id = std::str::from_utf8(&b[39..])
        .map_err(|_| refuse("invalid private diversity identifier"))?;
    if id.trim().is_empty() || id.contains('\0') {
        return Err(refuse("invalid private diversity identifier"));
    }
    let mode = match b[6] {
        0 => DiversityMode::UniqueBuild { nonce: id.into() },
        1 => DiversityMode::ReproduciblePrivate {
            reproduction_id: id.into(),
        },
        _ => return Err(refuse("unsupported diversity mode")),
    };
    Ok((
        PrivateBuildSeed::new(b[7..39].to_vec())
            .map_err(|_| refuse("invalid private diversity seed"))?,
        mode,
    ))
}
#[cfg(all(test, unix))]
mod tests {
    use super::super::workspace::{private_write, Workspace};
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn private_capture_rejects_symlinks_public_permissions_and_oversize() -> Result<()> {
        let w = Workspace::create(&std::env::temp_dir())?;
        let p = w.path.join("root.key");
        private_write(&p, &[17; 32])?;
        assert_eq!(read_key(&p)?.as_ref(), &[17; 32]);
        let alias = w.path.join("alias.key");
        symlink(&p, &alias)?;
        assert!(read_key(&alias).is_err());
        assert!(read_private(&p, 31).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644))?;
        assert!(read_key(&p).is_err());
        Ok(())
    }
}
