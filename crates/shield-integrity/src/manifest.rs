use crate::artifact::ArtifactIntegrity;
use crate::distributed::DistributionPlan;
use crate::error::{IntegrityError, Result};
use crate::graph::IntegrityGraph;
use crate::identity::{CertificateBinding, PackageBinding};
use crate::region::DexIntegrity;
use crate::response::ResponsePolicy;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const INTEGRITY_MANIFEST_SCHEMA: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityManifest {
    pub schema: u32,
    pub build_id: String,
    pub certificate: CertificateBinding,
    pub package: PackageBinding,
    pub dex_files: Vec<DexIntegrity>,
    pub artifacts: Vec<ArtifactIntegrity>,
    pub graph: IntegrityGraph,
    pub distribution: DistributionPlan,
    pub response_policy: ResponsePolicy,
}

impl IntegrityManifest {
    pub fn build(
        build_id: impl Into<String>,
        certificate: CertificateBinding,
        package: PackageBinding,
        mut dex_files: Vec<DexIntegrity>,
        mut artifacts: Vec<ArtifactIntegrity>,
        distribution_seed: &[u8],
        check_count: u32,
        redundancy: u8,
        response_policy: ResponsePolicy,
    ) -> Result<Self> {
        let build_id = build_id.into();
        if build_id.trim().is_empty() || build_id.as_bytes().contains(&0) {
            return Err(IntegrityError::InvalidManifest(
                "build_id must be non-empty and contain no NUL".into(),
            ));
        }

        dex_files.sort_by(|left, right| left.name.cmp(&right.name));
        artifacts.sort_by(|left, right| left.path.cmp(&right.path));
        validate_unique_inputs(&dex_files, &artifacts)?;

        let graph = IntegrityGraph::build(&certificate, &package, &dex_files, &artifacts)?;
        let distribution =
            DistributionPlan::compile(&graph, distribution_seed, check_count, redundancy)?;

        let manifest = Self {
            schema: INTEGRITY_MANIFEST_SCHEMA,
            build_id,
            certificate,
            package,
            dex_files,
            artifacts,
            graph,
            distribution,
            response_policy,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != INTEGRITY_MANIFEST_SCHEMA {
            return Err(IntegrityError::InvalidManifest(format!(
                "unsupported schema {}",
                self.schema
            )));
        }
        if self.build_id.trim().is_empty() || self.build_id.as_bytes().contains(&0) {
            return Err(IntegrityError::InvalidManifest(
                "build_id must be non-empty and contain no NUL".into(),
            ));
        }
        validate_unique_inputs(&self.dex_files, &self.artifacts)?;

        let rebuilt = IntegrityGraph::build(
            &self.certificate,
            &self.package,
            &self.dex_files,
            &self.artifacts,
        )?;
        if rebuilt != self.graph {
            return Err(IntegrityError::InvalidManifest(
                "integrity graph does not match manifest bindings/artifacts".into(),
            ));
        }
        self.graph.validate()?;
        self.distribution.validate(&self.graph)?;
        Ok(())
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        self.validate()?;
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    pub fn from_json(value: &str) -> Result<Self> {
        let manifest: Self = serde_json::from_str(value)?;
        manifest.validate()?;
        Ok(manifest)
    }
}

fn validate_unique_inputs(
    dex_files: &[DexIntegrity],
    artifacts: &[ArtifactIntegrity],
) -> Result<()> {
    let dex_names = dex_files
        .iter()
        .map(|dex| dex.name.as_str())
        .collect::<BTreeSet<_>>();
    if dex_names.len() != dex_files.len() {
        return Err(IntegrityError::InvalidManifest(
            "duplicate DEX names in integrity manifest".into(),
        ));
    }
    let artifact_paths = artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<BTreeSet<_>>();
    if artifact_paths.len() != artifacts.len() {
        return Err(IntegrityError::InvalidManifest(
            "duplicate artifact paths in integrity manifest".into(),
        ));
    }
    Ok(())
}
