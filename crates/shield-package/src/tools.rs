use crate::error::{PackageError, Result};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Explicit Android signing inputs. Password values are resolved by apksigner from environment variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningConfig {
    pub keystore: PathBuf,
    pub key_alias: String,
    pub keystore_password_env: String,
    pub key_password_env: Option<String>,
    pub min_sdk: u32,
    pub v1: bool,
    pub v2: bool,
    pub v3: bool,
}

impl SigningConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.keystore.is_file() {
            return Err(PackageError::InvalidArgument(format!(
                "keystore '{}' does not exist",
                self.keystore.display()
            )));
        }
        if self.key_alias.is_empty() {
            return Err(PackageError::InvalidArgument(
                "signing key alias must not be empty".into(),
            ));
        }
        require_env(&self.keystore_password_env)?;
        if let Some(name) = &self.key_password_env {
            require_env(name)?;
        }
        Ok(())
    }
}

/// Paths to official Android Build Tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidTools {
    pub zipalign: PathBuf,
    pub apksigner: PathBuf,
}

impl AndroidTools {
    pub fn discover(
        zipalign_override: Option<&Path>,
        apksigner_override: Option<&Path>,
    ) -> Result<Self> {
        let zipalign = match zipalign_override {
            Some(path) => validate_tool(path, "zipalign")?,
            None => discover_build_tool("zipalign")?,
        };
        let apksigner = match apksigner_override {
            Some(path) => validate_tool(path, "apksigner")?,
            None => discover_build_tool("apksigner")?,
        };

        Ok(Self {
            zipalign,
            apksigner,
        })
    }

    pub fn align(&self, input: &Path, output: &Path) -> Result<()> {
        let args = [
            OsString::from("-P"),
            OsString::from("16"),
            OsString::from("-f"),
            OsString::from("4"),
            input.as_os_str().to_owned(),
            output.as_os_str().to_owned(),
        ];
        run_checked(&self.zipalign, &args)?;

        let verify_args = [
            OsString::from("-c"),
            OsString::from("-P"),
            OsString::from("16"),
            OsString::from("4"),
            output.as_os_str().to_owned(),
        ];
        run_checked(&self.zipalign, &verify_args)?;
        Ok(())
    }

    pub fn sign(&self, input: &Path, output: &Path, config: &SigningConfig) -> Result<()> {
        config.validate()?;

        let mut args = vec![
            OsString::from("sign"),
            OsString::from("--min-sdk-version"),
            OsString::from(config.min_sdk.to_string()),
            OsString::from("--ks"),
            config.keystore.as_os_str().to_owned(),
            OsString::from("--ks-key-alias"),
            OsString::from(&config.key_alias),
            OsString::from("--ks-pass"),
            OsString::from(format!("env:{}", config.keystore_password_env)),
        ];

        if let Some(variable) = &config.key_password_env {
            args.push(OsString::from("--key-pass"));
            args.push(OsString::from(format!("env:{variable}")));
        }

        append_bool_option(&mut args, "--v1-signing-enabled", config.v1);
        append_bool_option(&mut args, "--v2-signing-enabled", config.v2);
        append_bool_option(&mut args, "--v3-signing-enabled", config.v3);
        append_bool_option(&mut args, "--v4-signing-enabled", false);

        args.push(OsString::from("--out"));
        args.push(output.as_os_str().to_owned());
        args.push(input.as_os_str().to_owned());

        run_checked(&self.apksigner, &args)?;
        self.verify_signature(output, config.min_sdk)?;
        Ok(())
    }

    pub fn verify_signature(&self, apk: &Path, min_sdk: u32) -> Result<String> {
        let args = [
            OsString::from("verify"),
            OsString::from("--min-sdk-version"),
            OsString::from(min_sdk.to_string()),
            OsString::from("--verbose"),
            OsString::from("--print-certs"),
            apk.as_os_str().to_owned(),
        ];
        let output = run_checked(&self.apksigner, &args)?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

fn append_bool_option(args: &mut Vec<OsString>, name: &str, value: bool) {
    args.push(OsString::from(name));
    args.push(OsString::from(if value { "true" } else { "false" }));
}

fn run_checked(tool: &Path, args: &[OsString]) -> Result<Output> {
    let output = Command::new(tool).args(args).output()?;
    if !output.status.success() {
        return Err(PackageError::ToolFailed {
            tool: tool.to_path_buf(),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(output)
}

fn validate_tool(path: &Path, name: &str) -> Result<PathBuf> {
    if path.is_file() {
        Ok(path.to_path_buf())
    } else {
        Err(PackageError::ToolNotFound(format!(
            "{name} at '{}'",
            path.display()
        )))
    }
}

fn require_env(name: &str) -> Result<()> {
    if env::var_os(name).is_none() {
        return Err(PackageError::MissingEnvironmentVariable(name.to_owned()));
    }
    Ok(())
}

fn discover_build_tool(name: &str) -> Result<PathBuf> {
    let sdk_root = env::var_os("ANDROID_SDK_ROOT")
        .or_else(|| env::var_os("ANDROID_HOME"))
        .ok_or_else(|| {
            PackageError::ToolNotFound(format!(
                "{name}; set ANDROID_SDK_ROOT/ANDROID_HOME or pass an explicit path"
            ))
        })?;

    let build_tools = PathBuf::from(sdk_root).join("build-tools");
    let mut versions = fs::read_dir(&build_tools)?
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();

    versions.sort_by(|left, right| compare_version_paths(right, left));

    for version in versions {
        for candidate in tool_candidates(name) {
            let path = version.join(candidate);
            if path.is_file() {
                return Ok(path);
            }
        }
    }

    Err(PackageError::ToolNotFound(format!(
        "{name} under '{}'",
        build_tools.display()
    )))
}

fn tool_candidates(name: &str) -> [String; 2] {
    [name.to_owned(), format!("{name}.bat")]
}

fn compare_version_paths(left: &Path, right: &Path) -> std::cmp::Ordering {
    let left_name = left
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let right_name = right
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();

    version_key(left_name).cmp(&version_key(right_name))
}

fn version_key(value: &str) -> Vec<u32> {
    value
        .split(['.', '-'])
        .map(|part| part.parse::<u32>().unwrap_or(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::version_key;

    #[test]
    fn numeric_version_sorting_is_not_lexicographic() {
        assert!(version_key("35.0.0") > version_key("9.0.0"));
        assert!(version_key("36.0.0") > version_key("35.0.1"));
    }
}
