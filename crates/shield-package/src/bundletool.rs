use crate::error::{PackageError, Result};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApkSetMode {
    Default,
    Universal,
}

impl ApkSetMode {
    const fn as_str(self) -> Option<&'static str> {
        match self {
            Self::Default => None,
            Self::Universal => Some("universal"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundletoolSigningConfig {
    pub keystore: PathBuf,
    pub key_alias: String,
    pub keystore_password_file: PathBuf,
    pub key_password_file: Option<PathBuf>,
}

impl BundletoolSigningConfig {
    /// Validates bundletool signing material without reading password contents.
    ///
    /// # Errors
    ///
    /// Returns an error when the keystore/password files do not exist or the
    /// signing alias is empty.
    pub fn validate(&self) -> Result<()> {
        for path in [&self.keystore, &self.keystore_password_file] {
            if !path.is_file() {
                return Err(PackageError::InvalidArgument(format!(
                    "bundletool signing input '{}' does not exist",
                    path.display()
                )));
            }
        }
        if let Some(path) = &self.key_password_file {
            if !path.is_file() {
                return Err(PackageError::InvalidArgument(format!(
                    "bundletool key password file '{}' does not exist",
                    path.display()
                )));
            }
        }
        if self.key_alias.trim().is_empty() {
            return Err(PackageError::InvalidArgument(
                "bundletool signing key alias must not be empty".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundletool {
    pub java: PathBuf,
    pub jar: PathBuf,
}

impl Bundletool {
    /// Creates a bundletool wrapper from explicit Java and JAR paths.
    ///
    /// # Errors
    ///
    /// Returns an error when the bundletool JAR is missing or the Java command
    /// path is empty.
    pub fn new(java: impl Into<PathBuf>, jar: impl Into<PathBuf>) -> Result<Self> {
        let tool = Self {
            java: java.into(),
            jar: jar.into(),
        };
        tool.validate_paths()?;
        Ok(tool)
    }

    /// Runs official bundletool validation for an Android App Bundle.
    ///
    /// # Errors
    ///
    /// Returns an error when the bundle is missing, Java cannot execute, or
    /// bundletool rejects the bundle.
    pub fn validate_bundle(&self, bundle: &Path) -> Result<String> {
        require_file(bundle, "AAB")?;
        let args = vec![
            OsString::from("-jar"),
            self.jar.as_os_str().to_owned(),
            OsString::from("validate"),
            OsString::from(format!("--bundle={}", bundle.display())),
        ];
        let output = run_checked(&self.java, &args)?;
        Ok(combined_output(&output))
    }

    /// Generates an APK Set with official bundletool.
    ///
    /// # Errors
    ///
    /// Returns an error for missing inputs, invalid signing material, tool
    /// execution failure, or when bundletool does not create the output.
    pub fn build_apks(
        &self,
        bundle: &Path,
        output: &Path,
        mode: ApkSetMode,
        local_testing: bool,
        signing: Option<&BundletoolSigningConfig>,
    ) -> Result<String> {
        require_file(bundle, "AAB")?;
        if let Some(config) = signing {
            config.validate()?;
        }

        let mut args = vec![
            OsString::from("-jar"),
            self.jar.as_os_str().to_owned(),
            OsString::from("build-apks"),
            OsString::from(format!("--bundle={}", bundle.display())),
            OsString::from(format!("--output={}", output.display())),
            OsString::from("--overwrite"),
        ];

        if let Some(mode) = mode.as_str() {
            args.push(OsString::from(format!("--mode={mode}")));
        }
        if local_testing {
            args.push(OsString::from("--local-testing"));
        }
        if let Some(config) = signing {
            args.extend([
                OsString::from(format!("--ks={}", config.keystore.display())),
                OsString::from(format!("--ks-key-alias={}", config.key_alias)),
                OsString::from(format!(
                    "--ks-pass=file:{}",
                    config.keystore_password_file.display()
                )),
            ]);
            if let Some(path) = &config.key_password_file {
                args.push(OsString::from(format!(
                    "--key-pass=file:{}",
                    path.display()
                )));
            }
        }

        let output_result = run_checked(&self.java, &args)?;
        if !output.is_file() {
            return Err(PackageError::VerificationFailed(format!(
                "bundletool did not create APK Set '{}'",
                output.display()
            )));
        }
        Ok(combined_output(&output_result))
    }

    fn validate_paths(&self) -> Result<()> {
        if !self.jar.is_file() {
            return Err(PackageError::ToolNotFound(format!(
                "bundletool JAR at '{}'",
                self.jar.display()
            )));
        }
        if self.java.as_os_str().is_empty() {
            return Err(PackageError::ToolNotFound("java".into()));
        }
        Ok(())
    }
}

fn require_file(path: &Path, label: &str) -> Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        Err(PackageError::InvalidArgument(format!(
            "{label} '{}' does not exist",
            path.display()
        )))
    }
}

fn run_checked(tool: &Path, args: &[OsString]) -> Result<Output> {
    let output = Command::new(tool).args(args).output()?;
    if !output.status.success() {
        return Err(PackageError::ToolFailed {
            tool: tool.to_path_buf(),
            status: output.status.code(),
            stderr: combined_output(&output),
        });
    }
    Ok(output)
}

fn combined_output(output: &Output) -> String {
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        if !combined.is_empty() && !combined.ends_with('\n') {
            combined.push('\n');
        }
        combined.push_str(&stderr);
    }
    combined
}
