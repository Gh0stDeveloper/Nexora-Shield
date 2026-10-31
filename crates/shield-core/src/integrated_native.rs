//! Native compilation owned by the common engine, with private bounded outputs.
use super::{
    config::{read_private, BuildTools},
    workspace::Workspace,
};
use crate::{runtime_smali::refuse, Result};
use nexora_shield_crypto::{hex_lower, sha256};
use nexora_shield_native::RuntimeImage;
use nexora_shield_package::sha256_file;
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
pub(super) struct NativeBuild {
    pub directory: PathBuf,
    pub source_sha256: String,
    pub versions: BTreeMap<String, String>,
}
pub(super) fn compile(
    tools: &BuildTools,
    image: &RuntimeImage,
    config: &Path,
    work: &Path,
) -> Result<NativeBuild> {
    let source = validated_source(tools)?;
    let source_sha256 = source_fingerprint(&source)?;
    let configuration_sha256 = verify_configuration(config, image)?;
    let versions = compiler_versions(tools, work)?;
    private_cache(&tools.native_cache)?;
    let cache = tools
        .native_cache
        .join(format!("{source_sha256}-{configuration_sha256}"));
    let directory = work.join("jniLibs");
    fs::create_dir(&directory)?;
    let session = BuildSession {
        tools,
        image,
        config,
        work,
        source: &source,
        cache: &cache,
        configuration_sha256: &configuration_sha256,
    };
    for (target, abi, linker) in [
        (
            "aarch64-linux-android",
            "arm64-v8a",
            "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER",
        ),
        (
            "x86_64-linux-android",
            "x86_64",
            "CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER",
        ),
    ] {
        let bytes = session.build_abi(target, abi, linker)?;
        let out = directory.join(abi);
        fs::create_dir(&out)?;
        fs::write(out.join("libnexora_shield_native.so"), bytes)?;
    }
    if source_fingerprint(&source)? != source_sha256 {
        return Err(refuse(
            "native source changed during integrated compilation",
        ));
    }
    Ok(NativeBuild {
        directory,
        source_sha256,
        versions,
    })
}
struct BuildSession<'a> {
    tools: &'a BuildTools,
    image: &'a RuntimeImage,
    config: &'a Path,
    work: &'a Path,
    source: &'a Path,
    cache: &'a Path,
    configuration_sha256: &'a str,
}
impl BuildSession<'_> {
    fn build_abi(&self, target: &str, abi: &str, linker: &str) -> Result<Vec<u8>> {
        if verify_configuration(self.config, self.image)? != self.configuration_sha256 {
            return Err(refuse(
                "private runtime configuration changed before ABI compilation",
            ));
        }
        let target_dir = self.cache.join(target);
        let compiler = self
            .tools
            .ndk_directory
            .join("toolchains/llvm/prebuilt/linux-x86_64/bin")
            .join(format!("{target}24-clang"));
        if !compiler.is_file() {
            return Err(refuse(
                "pinned Android cross compiler is unavailable on this host",
            ));
        }
        let mut c = Command::new(&self.tools.cargo);
        c.current_dir(self.source)
            .args([
                "build",
                "--locked",
                "--release",
                "-p",
                "nexora-shield-native",
                "--features",
                "android-runtime",
                "--target",
                target,
            ])
            .env("NEXORA_RUNTIME_IMAGE", self.config)
            .env("CARGO_TARGET_DIR", &target_dir)
            .env("CARGO_BUILD_BUILD_DIR", &target_dir)
            .env("RUSTC", &self.tools.rustc)
            .env("RUSTUP_TOOLCHAIN", "1.99.1")
            .env(linker, compiler)
            .env("RUSTC_WRAPPER", "")
            .env("RUSTC_WORKSPACE_WRAPPER", "")
            .env("RUSTFLAGS", "")
            .env("CARGO_ENCODED_RUSTFLAGS", "");
        let _ = run(
            &mut c,
            self.work,
            Duration::from_secs(1200),
            "native compilation",
        )?;
        if verify_configuration(self.config, self.image)? != self.configuration_sha256 {
            return Err(refuse(
                "private runtime configuration changed during ABI compilation",
            ));
        }
        let bytes = crate::runtime_smali::read_bounded(
            &target_dir
                .join(target)
                .join("release/libnexora_shield_native.so"),
            64 * 1024 * 1024,
        )?;
        verify_library(&bytes, abi, self.image)?;
        Ok(bytes)
    }
}
fn validated_source(tools: &BuildTools) -> Result<PathBuf> {
    let source = fs::canonicalize(&tools.native_source)?;
    if !source.join("crates/shield-native/Cargo.toml").is_file() {
        return Err(refuse("native source must be a Nexora workspace"));
    }
    let revision = fs::read_to_string(tools.ndk_directory.join("source.properties"))?;
    if !revision
        .lines()
        .any(|l| l.trim() == "Pkg.Revision = 27.3.13750724")
    {
        return Err(refuse(
            "native compilation requires pinned NDK 27.3.13750724",
        ));
    }
    Ok(source)
}
fn verify_configuration(path: &Path, image: &RuntimeImage) -> Result<String> {
    let bytes = read_private(path, 32 * 1024 * 1024)?;
    let actual: RuntimeImage = serde_json::from_slice(&bytes)
        .map_err(|_| refuse("invalid private runtime configuration"))?;
    if actual != *image {
        return Err(refuse(
            "private runtime configuration differs from frozen plan",
        ));
    }
    Ok(hex_lower(&sha256(&bytes)))
}
fn compiler_versions(tools: &BuildTools, work: &Path) -> Result<BTreeMap<String, String>> {
    let mut v = BTreeMap::new();
    for (name, path, prefix) in [
        ("rustc", &tools.rustc, "rustc 1.99.1 "),
        ("cargo", &tools.cargo, "cargo 1.99.1 "),
    ] {
        let mut c = Command::new(path);
        c.arg("--version").env("RUSTUP_TOOLCHAIN", "1.99.1");
        let value = run(&mut c, work, Duration::from_secs(30), name)?;
        let value = value.trim();
        if !value.starts_with(prefix) || value.contains('\n') {
            return Err(refuse("native compiler does not match pinned toolchain"));
        }
        v.insert(name.into(), value.into());
    }
    v.insert("ndk".into(), "27.3.13750724".into());
    v.insert(
        "smali".into(),
        "3.0.9; verified pinned jar inventory".into(),
    );
    Ok(v)
}
pub(super) fn verify_library(bytes: &[u8], abi: &str, image: &RuntimeImage) -> Result<()> {
    let machine = match abi {
        "arm64-v8a" => 183,
        "x86_64" => 62,
        _ => return Err(refuse("unsupported runtime ABI")),
    };
    let marker = format!(
        "NEXORA_RUNTIME_V1:{}",
        image
            .fingerprint()
            .map_err(|_| refuse("invalid runtime image fingerprint"))?
    );
    if bytes.len() < 20
        || &bytes[..6] != b"\x7fELF\x02\x01"
        || u16::from_le_bytes([bytes[18], bytes[19]]) != machine
        || occurrences(bytes, marker.as_bytes()) != 1
        || image
            .entries
            .iter()
            .any(|e| occurrences(bytes, &e.ciphertext) != 1)
    {
        return Err(refuse(
            "compiled native library differs from frozen ABI/runtime payload",
        ));
    }
    Ok(())
}
fn occurrences(bytes: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        0
    } else {
        bytes.windows(needle.len()).filter(|b| *b == needle).count()
    }
}
fn private_cache(path: &Path) -> Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)?;
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() {
        return Err(refuse("native cache must be a private directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if m.permissions().mode() & 0o077 != 0 {
            return Err(refuse(
                "native cache contains private build material and requires mode 0700",
            ));
        }
    }
    Ok(())
}
fn source_fingerprint(root: &Path) -> Result<String> {
    let mut files = BTreeMap::new();
    for n in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"] {
        record_source(root, &root.join(n), &mut files)?;
    }
    for e in fs::read_dir(root.join("crates"))? {
        let p = e?.path();
        if !fs::symlink_metadata(&p)?.is_dir() {
            return Err(refuse("unexpected native workspace entry"));
        }
        record_source(root, &p.join("Cargo.toml"), &mut files)?;
        if p.join("build.rs").exists() {
            record_source(root, &p.join("build.rs"), &mut files)?;
        }
        visit_source(root, &p.join("src"), &mut files)?;
    }
    let data =
        serde_json::to_vec(&files).map_err(|_| refuse("source fingerprint encoding failed"))?;
    Ok(hex_lower(&sha256(&data)))
}
fn visit_source(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) -> Result<()> {
    for e in fs::read_dir(path)? {
        let p = e?.path();
        if fs::symlink_metadata(&p)?.is_dir() {
            visit_source(root, &p, files)?;
        } else {
            record_source(root, &p, files)?;
        }
    }
    Ok(())
}
fn record_source(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() || m.len() > 4 * 1024 * 1024 || files.len() > 10000 {
        return Err(refuse(
            "native source inventory exceeds its supported bounds",
        ));
    }
    let n = path
        .strip_prefix(root)
        .map_err(|_| refuse("native source escaped its workspace"))?
        .to_str()
        .ok_or_else(|| refuse("invalid source name"))?;
    files.insert(n.into(), sha256_file(path)?);
    Ok(())
}
pub(super) fn run(c: &mut Command, work: &Path, timeout: Duration, label: &str) -> Result<String> {
    let capture = Workspace::create(work)?;
    let path = capture.path.join("tool-output");
    let out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    let mut child = c
        .stdin(Stdio::null())
        .stdout(out.try_clone()?)
        .stderr(out)
        .spawn()?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(refuse(&format!(
                    "{label} failed; private tool diagnostics withheld"
                )));
            }
            let mut b = Vec::new();
            fs::File::open(&path)?
                .take(8 * 1024 * 1024 + 1)
                .read_to_end(&mut b)?;
            if b.len() > 8 * 1024 * 1024 {
                return Err(refuse("integrated tool output exceeded its bound"));
            }
            return Ok(String::from_utf8_lossy(&b).into_owned());
        }
        if start.elapsed() > timeout || fs::metadata(&path)?.len() > 8 * 1024 * 1024 {
            let _ = child.kill();
            let _ = child.wait();
            return Err(refuse("integrated tool exceeded its execution budget"));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}
