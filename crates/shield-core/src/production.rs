//! Phase O.1 typed production stage contract (planning only).
//! No stage is reported as executed without final-artifact evidence.

use crate::{CoreError, PipelineResult, ProtectionProfile, ProtectionRequest, Result};
use nexora_shield_package::verify_apk_structure;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageRequirement {
    Required,
    WhenSelected,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageIntegration {
    /// Available only to inspect a request; never sufficient for publication.
    ReadOnlyPlanning,
    /// Exercised on a diagnostic artifact without end-to-end Android defenses.
    DiagnosticOnly,
    /// No usable executor for this required production capability.
    NotIntegrated,
    /// Requires validated final-artifact evidence from the production executor.
    ProductionIntegrated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionStage {
    Inspect,
    Configure,
    DexParse,
    Compatibility,
    Selectors,
    DexTransform,
    DataProtection,
    NativeShield,
    VmShield,
    Diversity,
    IntegrityGraph,
    RaspRuntime,
    Attestation,
    Rebuild,
    Align,
    Sign,
    FinalVerify,
    Evidence,
}

impl ProductionStage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Configure => "configure",
            Self::DexParse => "dex-parse",
            Self::Compatibility => "compatibility",
            Self::Selectors => "selectors",
            Self::DexTransform => "dex-transform",
            Self::DataProtection => "data-protection",
            Self::NativeShield => "native-shield",
            Self::VmShield => "vm-shield",
            Self::Diversity => "diversity",
            Self::IntegrityGraph => "integrity-graph",
            Self::RaspRuntime => "rasp-runtime",
            Self::Attestation => "attestation",
            Self::Rebuild => "rebuild",
            Self::Align => "align",
            Self::Sign => "sign",
            Self::FinalVerify => "final-verify",
            Self::Evidence => "evidence",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedStage {
    pub stage: ProductionStage,
    pub requirement: StageRequirement,
    pub integration: StageIntegration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionBuildContext {
    input: PathBuf,
    output: PathBuf,
    input_sha256: String,
    dex_count: usize,
    profile: ProtectionProfile,
    stages: Vec<PlannedStage>,
}

/// Public production entry point. It can NEVER silently fall back to Phase A
/// ZIP normalization when mandatory protection controls are unavailable.
///
/// # Errors
///
/// Returns a fail-closed error until the entire release production path is
/// implemented and verified. No output or reports are published on failure.
pub fn protect_production_apk(request: &ProtectionRequest) -> Result<PipelineResult> {
    let plan = ProductionBuildContext::prepare(request)?;
    let _ = plan.inspect_dex()?;
    plan.ensure_ready()?;
    // Even if the stage-status graph is mistakenly marked complete in future,
    // no output may be published until the actual executor is implemented.
    Err(CoreError::InvalidRequest(
        "production executor is not yet integrated: no protected APK was created".into(),
    ))
}

/// Resolve an intended file path, including symlinked ancestors, without
/// requiring the final file to exist. Reject dangling symlinks.
pub(crate) fn normalized_destination(path: &Path) -> Result<PathBuf> {
    if fs::symlink_metadata(path).is_ok() {
        return Ok(fs::canonicalize(path)?);
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    // Resolve the longest EXISTING prefix using OS path semantics before
    // appending any missing suffix. Lexical '..' collapsing before symlink
    // resolution is incorrect and may miss a clobbering alias.
    let mut cursor = absolute.as_path();
    let mut suffix = Vec::new();
    while !cursor.exists() {
        let name = cursor
            .file_name()
            .ok_or_else(|| CoreError::InvalidRequest("cannot resolve destination path".into()))?;
        suffix.push(name.to_os_string());
        cursor = cursor
            .parent()
            .ok_or_else(|| CoreError::InvalidRequest("destination has no parent".into()))?;
    }
    let mut canonical = fs::canonicalize(cursor)?;
    for name in suffix.iter().rev() {
        canonical.push(name);
    }
    Ok(canonical)
}

/// Disallow output/report clobbering of input, signing keys or each other.
/// This runs before any publication or report writes.
pub(crate) fn validate_reserved_paths(request: &ProtectionRequest) -> Result<()> {
    let mut paths = vec![
        ("input APK", &request.input),
        ("output APK", &request.output),
    ];
    if let Some(signing) = &request.signing {
        paths.push(("signing keystore", &signing.keystore));
    }
    if let Some(path) = &request.public_report {
        paths.push(("public report", path));
    }
    if let Some(path) = &request.private_report {
        paths.push(("private report", path));
    }
    let mut identities = std::collections::BTreeMap::new();
    for (label, path) in paths {
        let identity = normalized_destination(path)?;
        if let Some(previous) = identities.insert(identity, label) {
            return Err(CoreError::InvalidRequest(format!(
                "artifact path collision between {previous} and {label}"
            )));
        }
    }
    Ok(())
}

impl ProductionBuildContext {
    /// The inspected input path. The snapshot must be revalidated at execution.
    #[must_use]
    pub fn input(&self) -> &Path {
        &self.input
    }

    #[must_use]
    pub fn output(&self) -> &Path {
        &self.output
    }

    #[must_use]
    pub fn input_sha256(&self) -> &str {
        &self.input_sha256
    }

    #[must_use]
    pub const fn dex_count(&self) -> usize {
        self.dex_count
    }

    #[must_use]
    pub const fn profile(&self) -> ProtectionProfile {
        self.profile
    }

    #[must_use]
    pub fn stages(&self) -> &[PlannedStage] {
        &self.stages
    }

    /// Creates an immutable, read-only plan; never creates an output or report.
    ///
    /// # Errors
    ///
    /// Rejects malformed APK inputs, invalid output targets and unsafe signing policy.
    pub fn prepare(request: &ProtectionRequest) -> Result<Self> {
        if !request.input.is_file() {
            return Err(CoreError::InvalidRequest("input APK is not a file".into()));
        }
        validate_reserved_paths(request)?;
        if request.input == request.output
            || (request.output.exists()
                && fs::canonicalize(&request.input)? == fs::canonicalize(&request.output)?)
        {
            return Err(CoreError::InvalidRequest(
                "input/output refer to the same file".into(),
            ));
        }
        if request.output.exists() && !request.overwrite {
            return Err(CoreError::InvalidRequest("output already exists".into()));
        }
        if request.signing.is_none() && !request.allow_unsigned {
            return Err(CoreError::InvalidRequest(
                "unsigned production output requires explicit consent".into(),
            ));
        }
        if request.public_report.is_some() && request.public_report == request.private_report {
            return Err(CoreError::InvalidRequest("report paths must differ".into()));
        }
        let inspected = verify_apk_structure(&request.input)?;
        if inspected.dex_files.is_empty() {
            return Err(CoreError::InvalidRequest(
                "APK contains no DEX for production code protection".into(),
            ));
        }
        Ok(Self {
            input: request.input.clone(),
            output: request.output.clone(),
            input_sha256: inspected.sha256,
            dex_count: inspected.dex_files.len(),
            profile: request.profile,
            stages: Self::stage_graph(request.profile, request.align, request.signing.is_some()),
        })
    }

    /// Mandatory stages that are not yet implemented in the production pipeline.
    #[must_use]
    pub fn required_unintegrated(&self) -> Vec<ProductionStage> {
        self.stages
            .iter()
            .filter(|s| {
                s.requirement == StageRequirement::Required
                    && s.integration != StageIntegration::ProductionIntegrated
            })
            .map(|s| s.stage)
            .collect()
    }

    /// Fails closed until mandatory integrations are implemented and verified.
    ///
    /// # Errors
    ///
    /// Returns an explicit error listing unavailable mandatory controls.
    pub fn ensure_ready(&self) -> Result<()> {
        let missing = self.required_unintegrated();
        if missing.is_empty() {
            return Ok(());
        }
        let missing_names = missing
            .iter()
            .map(|stage| stage.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        Err(CoreError::InvalidRequest(format!(
            "production protection unavailable; required stages not integrated: {missing_names}"
        )))
    }

    fn stage_graph(profile: ProtectionProfile, align: bool, sign: bool) -> Vec<PlannedStage> {
        use ProductionStage as S;
        use StageIntegration as I;
        use StageRequirement as R;
        let order = [
            S::Inspect,
            S::Configure,
            S::DexParse,
            S::Compatibility,
            S::Selectors,
            S::DexTransform,
            S::DataProtection,
            S::NativeShield,
            S::VmShield,
            S::Diversity,
            S::IntegrityGraph,
            S::RaspRuntime,
            S::Attestation,
            S::Rebuild,
            S::Align,
            S::Sign,
            S::FinalVerify,
            S::Evidence,
        ];
        let hardened = profile != ProtectionProfile::Standard;
        order
            .into_iter()
            .map(|stage| {
                let requirement = match stage {
                    S::DataProtection | S::Diversity | S::RaspRuntime if !hardened => {
                        R::WhenSelected
                    }
                    S::NativeShield | S::VmShield if profile == ProtectionProfile::Maximum => {
                        R::Required
                    }
                    S::NativeShield | S::VmShield | S::Attestation => R::WhenSelected,
                    S::Align if !align => R::Disabled,
                    S::Sign if !sign => R::Disabled,
                    _ => R::Required,
                };
                let integration = match stage {
                    S::Inspect | S::Configure => I::ReadOnlyPlanning,
                    S::DexParse
                    | S::Compatibility
                    | S::Selectors
                    | S::DexTransform
                    | S::Rebuild
                    | S::FinalVerify => I::DiagnosticOnly,
                    _ => I::NotIntegrated,
                };
                PlannedStage {
                    stage,
                    requirement,
                    integration,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{ProductionBuildContext, ProductionStage as S, StageRequirement as R};
    use crate::ProtectionProfile;

    #[test]
    fn graph_is_ordered_and_complete() {
        let stages = ProductionBuildContext::stage_graph(ProtectionProfile::Maximum, true, true);
        assert_eq!(stages.len(), 18);
        assert_eq!(stages.first().map(|s| s.stage), Some(S::Inspect));
        assert_eq!(stages.last().map(|s| s.stage), Some(S::Evidence));
        assert!(stages.iter().all(|s| !s.stage.as_str().is_empty()));
    }

    #[test]
    fn profiles_differ_without_claiming_executed_protections() {
        let base = ProductionBuildContext::stage_graph(ProtectionProfile::Standard, false, false);
        let strict = ProductionBuildContext::stage_graph(ProtectionProfile::Hardened, false, false);
        assert!(base
            .iter()
            .any(|s| s.stage == S::DataProtection && s.requirement == R::WhenSelected));
        assert!(strict
            .iter()
            .any(|s| s.stage == S::DataProtection && s.requirement == R::Required));
        assert!(strict.iter().any(|s| {
            s.stage == S::DexTransform && s.integration == super::StageIntegration::DiagnosticOnly
        }));
        assert!(base
            .iter()
            .any(|s| s.stage == S::Sign && s.requirement == R::Disabled));
        let maximum = ProductionBuildContext::stage_graph(ProtectionProfile::Maximum, true, true);
        assert!(maximum
            .iter()
            .any(|s| s.stage == S::VmShield && s.requirement == R::Required));
        assert!(maximum
            .iter()
            .any(|s| s.stage == S::NativeShield && s.requirement == R::Required));
    }

    #[test]
    fn missing_mandatory_stages_fail_closed() {
        let ctx = ProductionBuildContext {
            input: "input.apk".into(),
            output: "out.apk".into(),
            input_sha256: "fixture".into(),
            dex_count: 1,
            profile: ProtectionProfile::Standard,
            stages: ProductionBuildContext::stage_graph(ProtectionProfile::Standard, true, true),
        };
        assert!(ctx.required_unintegrated().contains(&S::DexTransform));
        assert!(ctx.required_unintegrated().contains(&S::Inspect));
        assert!(ctx.required_unintegrated().contains(&S::Rebuild));
        assert!(ctx.ensure_ready().is_err());
    }
}
