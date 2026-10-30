use crate::{CoreError, Result};
use nexora_shield_package::sha256_file;
pub(crate) fn provider() -> String {
    include_str!("runtime_provider.smali").to_owned()
}
use std::fmt::Write as _;
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(crate) const HELPER: &str = "Ldev/nexora/shield/NativeShield;";

#[derive(Debug, Clone)]
pub struct SmaliTools {
    java: PathBuf,
    classpath: std::ffi::OsString,
}

impl SmaliTools {
    /// Validate pinned tool jars before executing them; never resolve an ambient classpath.
    /// # Errors
    /// Rejects missing executables, jars or checksum mismatches.
    pub fn new(java: &Path, directory: &Path) -> Result<Self> {
        let java = fs::canonicalize(java)?;
        if !java.is_file() {
            return Err(refuse("Java tool is not a file"));
        }
        let lock: serde_json::Value =
            serde_json::from_str(include_str!("../../../tools/smali-3.0.9.json"))
                .map_err(|_| refuse("invalid pinned smali inventory"))?;
        let mut paths = Vec::new();
        for entry in lock["artifacts"]
            .as_array()
            .ok_or_else(|| refuse("invalid tool inventory"))?
        {
            let path = directory.join(
                entry["name"]
                    .as_str()
                    .ok_or_else(|| refuse("invalid tool name"))?,
            );
            if sha256_file(&path)? != entry["sha256"].as_str().unwrap_or("") {
                return Err(refuse("smali jar checksum mismatch"));
            }
            paths.push(fs::canonicalize(path)?);
        }
        let classpath =
            std::env::join_paths(paths).map_err(|_| refuse("invalid smali classpath"))?;
        Ok(Self { java, classpath })
    }

    pub(crate) fn disassemble(&self, dex: &Path, directory: &Path) -> Result<()> {
        self.run(
            "baksmali",
            &[
                "disassemble".as_ref(),
                dex.as_os_str(),
                "--api".as_ref(),
                "24".as_ref(),
                "--output".as_ref(),
                directory.as_os_str(),
            ],
        )
    }

    pub(crate) fn assemble(&self, directory: &Path, dex: &Path) -> Result<()> {
        self.run(
            "smali",
            &[
                "assemble".as_ref(),
                directory.as_os_str(),
                "--api".as_ref(),
                "24".as_ref(),
                "--output".as_ref(),
                dex.as_os_str(),
            ],
        )
    }

    fn run(&self, tool: &str, arguments: &[&std::ffi::OsStr]) -> Result<()> {
        let class = format!("com.android.tools.smali.{tool}.Main");
        // Parser errors may contain original strings; never copy tool output into public logs.
        let mut child = Command::new(&self.java)
            .arg("-Xmx512m")
            .arg("-cp")
            .arg(&self.classpath)
            .arg(class)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                return if status.success() {
                    Ok(())
                } else {
                    Err(refuse("bounded smali operation failed"))
                };
            }
            if start.elapsed() > Duration::from_secs(120) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(refuse("smali operation timed out"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

pub(crate) fn refuse(message: &str) -> CoreError {
    CoreError::InvalidRequest(message.to_owned())
}

pub(crate) fn replace_method(source: &str, signature: &str, body: &str) -> Result<String> {
    let lines = source.lines().collect::<Vec<_>>();
    let starts = lines
        .iter()
        .enumerate()
        .filter_map(|(i, line)| {
            let line = line.trim();
            (line.starts_with(".method ") && line.split_whitespace().last() == Some(signature))
                .then_some(i)
        })
        .collect::<Vec<_>>();
    let [start] = starts.as_slice() else {
        return Err(refuse("selected smali method is absent or ambiguous"));
    };
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find_map(|(i, line)| (line.trim() == ".end method").then_some(i))
        .ok_or_else(|| refuse("unterminated smali method"))?;
    if lines[start + 1..end]
        .iter()
        .any(|line| line.trim().starts_with(".annotation") || line.trim().starts_with(".param"))
    {
        return Err(refuse(
            "selected method annotations/parameter contracts require a verified binder",
        ));
    }
    let mut output = lines[..=*start].join("\n");
    output.push('\n');
    output.push_str(body);
    output.push_str("\n.end method\n");
    output.push_str(&lines[end + 1..].join("\n"));
    output.push('\n');
    Ok(output)
}

pub(crate) fn constant_stub(slot: u32, kind: char) -> Result<String> {
    let (class, unbox, wide) = match kind {
        'Z' => ("Boolean", "booleanValue()Z", false),
        'I' => ("Integer", "intValue()I", false),
        'J' => ("Long", "longValue()J", true),
        'F' => ("Float", "floatValue()F", false),
        'D' => ("Double", "doubleValue()D", true),
        _ => return Err(refuse("unsupported constant stub type")),
    };
    let result = if wide {
        "move-result-wide"
    } else {
        "move-result"
    };
    let ret = if wide { "return-wide" } else { "return" };
    Ok(format!("    .registers 2\n    const v0, 0x{slot:x}\n    invoke-static {{v0}}, {HELPER}->constant(I)Ljava/lang/Object;\n    move-result-object v0\n    check-cast v0, Ljava/lang/{class};\n    invoke-virtual {{v0}}, Ljava/lang/{class};->{unbox}\n    {result} v0\n    {ret} v0"))
}

pub(crate) fn string_stub(slot: u32) -> String {
    format!("    .registers 2\n    const v0, 0x{slot:x}\n    invoke-static {{v0}}, {HELPER}->string(I)Ljava/lang/String;\n    move-result-object v0\n    return-object v0")
}

pub(crate) fn int_stub(slot: u32, arguments: usize) -> String {
    let mut code = format!(
        "    .registers {}\n    const v0, 0x{arguments:x}\n    new-array v0, v0, [I\n",
        arguments + 2
    );
    for index in 0..arguments {
        let _ = write!(
            code,
            "    const v1, 0x{index:x}\n    aput p{index}, v0, v1\n"
        );
    }
    let _ = write!(code,"    const v1, 0x{slot:x}\n    invoke-static {{v1, v0}}, {HELPER}->run(I[I)I\n    move-result v0\n    return v0");
    code
}

pub(crate) fn helper(fingerprint: &str) -> String {
    format!(
        r#".class public final Ldev/nexora/shield/NativeShield;
.super Ljava/lang/Object;

.field public static guardStatus:I

.method static constructor <clinit>()V
    .registers 1
    const-string v0, "nexora_shield_native"
    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    const-string v0, "NEXORA_RUNTIME_V1:{fingerprint}"
    invoke-static {{v0}}, Ldev/nexora/shield/NativeShield;->nBind(Ljava/lang/String;)V
    return-void
.end method

.method public static openAsset(Landroid/content/res/AssetManager;Ljava/lang/String;)Ljava/io/InputStream;
    .registers 3
    const/4 v0, 0x2
    invoke-static {{p0, p1, v0}}, Ldev/nexora/shield/NativeShield;->nOpenAsset(Landroid/content/res/AssetManager;Ljava/lang/String;I)Ljava/io/InputStream;
    move-result-object v0
    return-object v0
.end method

.method public static openAsset(Landroid/content/res/AssetManager;Ljava/lang/String;I)Ljava/io/InputStream;
    .registers 3
    invoke-static {{p0, p1, p2}}, Ldev/nexora/shield/NativeShield;->nOpenAsset(Landroid/content/res/AssetManager;Ljava/lang/String;I)Ljava/io/InputStream;
    move-result-object p0
    return-object p0
.end method

.method private static native nOpenAsset(Landroid/content/res/AssetManager;Ljava/lang/String;I)Ljava/io/InputStream;
.end method

.method private static native nBind(Ljava/lang/String;)V
.end method

.method private static native nConstant(I)Ljava/lang/Object;
.end method

.method private static native nInt(I[I)I
.end method

.method private static native nString(I)Ljava/lang/String;
.end method

.method private static native nStart(Landroid/content/Context;)I
.end method

.method public static constant(I)Ljava/lang/Object;
    .registers 1
    invoke-static {{p0}}, Ldev/nexora/shield/NativeShield;->nConstant(I)Ljava/lang/Object;
    move-result-object p0
    return-object p0
.end method

.method public static install(Landroid/content/Context;)V
    .registers 3
    invoke-static {{p0}}, Ldev/nexora/shield/NativeShield;->nStart(Landroid/content/Context;)I
    move-result v0
    sput v0, Ldev/nexora/shield/NativeShield;->guardStatus:I
    invoke-static {{v0}}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;
    move-result-object v0
    const-string v1, "NEXORA_GUARD_STATUS="
    invoke-virtual {{v1, v0}}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    const-string v1, "NexoraGuard"
    invoke-static {{v1, v0}}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method

.method public static run(I[I)I
    .registers 2
    invoke-static {{p0, p1}}, Ldev/nexora/shield/NativeShield;->nInt(I[I)I
    move-result p0
    return p0
.end method

.method public static string(I)Ljava/lang/String;
    .registers 1
    invoke-static {{p0}}, Ldev/nexora/shield/NativeShield;->nString(I)Ljava/lang/String;
    move-result-object p0
    invoke-virtual {{p0}}, Ljava/lang/String;->intern()Ljava/lang/String;
    move-result-object p0
    return-object p0
.end method
"#
    )
}

pub(crate) fn source_inventory(root: &Path) -> Result<BTreeMap<PathBuf, String>> {
    let mut output = BTreeMap::new();
    let mut queue = vec![root.to_path_buf()];
    let mut total = 0usize;
    while let Some(directory) = queue.pop() {
        for item in fs::read_dir(directory)? {
            let item = item?;
            let kind = item.file_type()?;
            if kind.is_symlink() {
                return Err(refuse("smali tree contains a symlink"));
            }
            if kind.is_dir() {
                queue.push(item.path());
                continue;
            }
            if item.path().extension().and_then(|s| s.to_str()) != Some("smali") {
                return Err(refuse("unexpected smali output"));
            }
            let source = String::from_utf8(read_bounded(&item.path(), 256 * 1024 * 1024 - total)?)
                .map_err(|_| refuse("invalid smali text"))?;
            total = total
                .checked_add(source.len())
                .ok_or_else(|| refuse("smali inventory too large"))?;
            if total > 256 * 1024 * 1024 || output.len() >= 65535 {
                return Err(refuse("smali inventory too large"));
            }
            let normalized = source
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n");
            let relative = item
                .path()
                .strip_prefix(root)
                .map_err(|_| refuse("invalid smali path"))?
                .to_path_buf();
            output.insert(relative, normalized);
        }
    }
    Ok(output)
}

pub(crate) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(refuse("runtime input must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).map_err(|_| refuse("invalid runtime budget"))? + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(refuse("runtime input exceeds budget"));
    }
    Ok(bytes)
}

pub(crate) fn ordered_methods(source: &str) -> String {
    let mut prefix = String::new();
    let mut methods = Vec::new();
    let mut block = String::new();
    for line in source.lines() {
        if line.starts_with(".method ") || !block.is_empty() {
            block.push_str(line);
            block.push('\n');
            if line == ".end method" {
                methods.push(std::mem::take(&mut block));
            }
        } else if methods.is_empty() {
            prefix.push_str(line);
            prefix.push('\n');
        }
    }
    methods.sort_by_key(|method| {
        let header = method.lines().next().unwrap_or("");
        let direct = header.contains(" static ")
            || header.contains(" private ")
            || header.contains(" constructor ");
        (
            !direct,
            header.split_whitespace().last().unwrap_or("").to_owned(),
        )
    });
    for method in methods {
        prefix.push_str(&method);
        prefix.push('\n');
    }
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_preserves_owner_flags_and_other_methods() -> Result<()> {
        let source = ".class Ltest/A;\n.method public static value()I\n.registers 1\nconst/4 v0, 0x1\nreturn v0\n.end method\n.method public static keep()V\n.registers 0\nreturn-void\n.end method\n";
        let updated = replace_method(source, "value()I", &int_stub(7, 0))?;
        assert!(updated.contains(".method public static value()I"));
        assert!(updated.contains("NativeShield;->run(I[I)I"));
        assert!(updated
            .ends_with(".method public static keep()V\n.registers 0\nreturn-void\n.end method\n"));
        assert!(!updated.contains("const/4 v0, 0x1"));
        Ok(())
    }

    #[test]
    fn replacement_refuses_ambiguous_or_annotated_contracts() {
        let method = ".method public static value()I\n.annotation runtime Ltest/Keep;\n.end annotation\n.end method\n";
        assert!(replace_method(method, "value()I", &int_stub(0, 0)).is_err());
        assert!(replace_method(&method.repeat(2), "value()I", "").is_err());
        assert!(replace_method(method, "missing()I", "").is_err());
    }
}
