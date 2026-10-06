use crate::error::{CoreError, Result};
use crate::plan::BuildPlan;
use crate::report::{write_report_atomic, PrivateBuildReport, PublicBuildReport};
use crate::ProtectionProfile;
use nexora_shield_package::{
    inspect_apk, normalize_zip, verify_apk_structure, verify_normalized_equivalence, AndroidTools,
    ApkInspection, NormalizationSummary, SigningConfig,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Strict lifecycle states recorded by the Phase A transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineStage {
    Planned,
    Normalized,
    ContentVerified,
    Aligned,
    Signed,
    PackageVerified,
    Published,
}

impl PipelineStage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Normalized => "normalized",
            Self::ContentVerified => "content-verified",
            Self::Aligned => "aligned",
            Self::Signed => "signed",
            Self::PackageVerified => "package-verified",
            Self::Published => "published",
        }
    }
}

/// Full input contract for the Phase A protect operation.
#[derive(Debug, Clone)]
pub struct ProtectionRequest {
    pub input: PathBuf,
    pub output: PathBuf,
    pub profile: ProtectionProfile,
    pub align: bool,
    pub allow_unsigned: bool,
    pub overwrite: bool,
    pub signing: Option<SigningConfig>,
    pub zipalign: Option<PathBuf>,
    pub apksigner: Option<PathBuf>,
    pub public_report: Option<PathBuf>,
    pub private_report: Option<PathBuf>,
}

/// Successful pipeline output.
#[derive(Debug, Clone)]
pub struct PipelineResult {
    pub plan: BuildPlan,
    pub input_inspection: ApkInspection,
    pub output_inspection: ApkInspection,
    pub normalization: NormalizationSummary,
    pub aligned: bool,
    pub signed: bool,
    pub stages: Vec<PipelineStage>,
}

pub fn protect_apk(request: &ProtectionRequest) -> Result<PipelineResult> {
    validate_request(request)?;

    let input_inspection = verify_apk_structure(&request.input)?;
    let plan = BuildPlan::create(
        &request.input,
        &request.output,
        request.profile,
        &input_inspection,
        request.align,
        request.signing.is_some(),
    )?;

    let tools = if request.align || request.signing.is_some() {
        Some(AndroidTools::discover(
            request.zipalign.as_deref(),
            request.apksigner.as_deref(),
        )?)
    } else {
        None
    };

    let mut stages = vec![PipelineStage::Planned];
    let mut workspace = TransactionWorkspace::create(&request.output)?;
    let normalized = workspace.path().join("normalized.apk");

    let normalization = normalize_zip(&request.input, &normalized)?;
    stages.push(PipelineStage::Normalized);

    verify_normalized_equivalence(&request.input, &normalized)?;
    verify_apk_structure(&normalized)?;
    stages.push(PipelineStage::ContentVerified);

    let mut current = normalized;
    if request.align {
        let aligned = workspace.path().join("aligned.apk");
        tools
            .as_ref()
            .ok_or_else(|| CoreError::Transaction("zipalign tools were not initialized".into()))?
            .align(&current, &aligned)?;
        verify_normalized_equivalence(&current, &aligned)?;
        current = aligned;
        stages.push(PipelineStage::Aligned);
    }

    if let Some(signing) = &request.signing {
        let signed = workspace.path().join("signed.apk");
        tools
            .as_ref()
            .ok_or_else(|| CoreError::Transaction("apksigner tools were not initialized".into()))?
            .sign(&current, &signed, signing)?;
        current = signed;
        stages.push(PipelineStage::Signed);
    }

    let output_inspection = verify_apk_structure(&current)?;
    if output_inspection.dex_files.len() != plan.expected_dex_count {
        return Err(CoreError::Transaction(
            "DEX count changed during the Phase A packaging pipeline".into(),
        ));
    }
    stages.push(PipelineStage::PackageVerified);

    publish_atomic(&current, &request.output, request.overwrite)?;
    workspace.mark_published();
    stages.push(PipelineStage::Published);

    let published_inspection = inspect_apk(&request.output)?;
    let result = PipelineResult {
        plan,
        input_inspection,
        output_inspection: published_inspection,
        normalization,
        aligned: request.align,
        signed: request.signing.is_some(),
        stages,
    };

    if let Some(path) = &request.public_report {
        write_report_atomic(path, &PublicBuildReport::from_pipeline(&result).to_json())?;
    }
    if let Some(path) = &request.private_report {
        write_report_atomic(path, &PrivateBuildReport::from_pipeline(&result).to_json())?;
    }

    Ok(result)
}

fn validate_request(request: &ProtectionRequest) -> Result<()> {
    if !request.input.is_file() {
        return Err(CoreError::InvalidRequest(format!(
            "input APK '{}' does not exist",
            request.input.display()
        )));
    }

    if request.input == request.output {
        return Err(CoreError::InvalidRequest(
            "input and output APK paths must differ".into(),
        ));
    }

    if request.signing.is_none() && !request.allow_unsigned {
        return Err(CoreError::InvalidRequest(
            "refusing to emit an unsigned APK; configure signing or pass --unsigned explicitly"
                .into(),
        ));
    }

    if request.output.exists() && !request.overwrite {
        return Err(CoreError::InvalidRequest(format!(
            "output '{}' already exists; use --force to replace it",
            request.output.display()
        )));
    }

    if let (Some(public), Some(private)) = (&request.public_report, &request.private_report) {
        if public == private {
            return Err(CoreError::InvalidRequest(
                "public and private report paths must differ".into(),
            ));
        }
    }

    Ok(())
}

#[derive(Debug)]
struct TransactionWorkspace {
    path: PathBuf,
    published: bool,
}

impl TransactionWorkspace {
    fn create(output: &Path) -> Result<Self> {
        let parent = output.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| CoreError::Clock(error.to_string()))?
            .as_nanos();

        for attempt in 0_u32..32 {
            let candidate = parent.join(format!(
                ".nexora-shield-txn-{}-{timestamp:x}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    return Ok(Self {
                        path: candidate,
                        published: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }

        Err(CoreError::Transaction(
            "could not allocate a unique transaction directory".into(),
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn mark_published(&mut self) {
        self.published = true;
    }
}

impl Drop for TransactionWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn publish_atomic(source: &Path, output: &Path, overwrite: bool) -> Result<()> {
    if !output.exists() {
        fs::rename(source, output)?;
        return Ok(());
    }

    if !overwrite {
        return Err(CoreError::InvalidRequest(format!(
            "output '{}' already exists",
            output.display()
        )));
    }

    let backup = output.with_extension("nexora-shield.backup");
    if backup.exists() {
        fs::remove_file(&backup)?;
    }

    fs::rename(output, &backup)?;
    match fs::rename(source, output) {
        Ok(()) => {
            fs::remove_file(&backup)?;
            Ok(())
        }
        Err(error) => {
            let restore_result = fs::rename(&backup, output);
            if let Err(restore_error) = restore_result {
                return Err(CoreError::Transaction(format!(
                    "publish failed ({error}) and backup restore failed ({restore_error})"
                )));
            }
            Err(error.into())
        }
    }
}
