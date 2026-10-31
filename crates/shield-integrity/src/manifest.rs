use crate::artifact::ArtifactIntegrity;
use crate::distributed::DistributionPlan;
use crate::error::{IntegrityError, Result};
use crate::graph::{IntegrityGraph, IntegrityNodeKind};
use crate::identity::{CertificateBinding, PackageBinding};
use crate::region::DexIntegrity;
use crate::response::ResponsePolicy;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const INTEGRITY_MANIFEST_SCHEMA: u32 = 1;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestTopology {
    #[default]
    Canonical,
    CertificateTree,
}
impl ManifestTopology {
    fn is_canonical(&self) -> bool {
        *self == Self::Canonical
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributionConfig {
    pub seed: Vec<u8>,
    pub check_count: u32,
    pub redundancy: u8,
}

impl DistributionConfig {
    #[must_use]
    pub fn new(seed: impl Into<Vec<u8>>, check_count: u32, redundancy: u8) -> Self {
        Self {
            seed: seed.into(),
            check_count,
            redundancy,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityManifestInput {
    pub build_id: String,
    pub certificate: CertificateBinding,
    pub package: PackageBinding,
    pub dex_files: Vec<DexIntegrity>,
    pub artifacts: Vec<ArtifactIntegrity>,
    pub distribution: DistributionConfig,
    pub response_policy: ResponsePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityManifest {
    pub schema: u32,
    pub build_id: String,
    pub certificate: CertificateBinding,
    pub package: PackageBinding,
    pub dex_files: Vec<DexIntegrity>,
    pub artifacts: Vec<ArtifactIntegrity>,
    pub graph: IntegrityGraph,
    #[serde(default, skip_serializing_if = "ManifestTopology::is_canonical")]
    pub topology: ManifestTopology,
    pub distribution: DistributionPlan,
    pub response_policy: ResponsePolicy,
}

impl IntegrityManifest {
    pub fn build(mut input: IntegrityManifestInput) -> Result<Self> {
        if input.build_id.trim().is_empty() || input.build_id.as_bytes().contains(&0) {
            return Err(IntegrityError::InvalidManifest(
                "build_id must be non-empty and contain no NUL".into(),
            ));
        }

        input
            .dex_files
            .sort_by(|left, right| left.name.cmp(&right.name));
        input
            .artifacts
            .sort_by(|left, right| left.path.cmp(&right.path));
        validate_unique_inputs(&input.dex_files, &input.artifacts)?;

        let graph = IntegrityGraph::build(
            &input.certificate,
            &input.package,
            &input.dex_files,
            &input.artifacts,
        )?;
        let distribution = DistributionPlan::compile(
            &graph,
            &input.distribution.seed,
            input.distribution.check_count,
            input.distribution.redundancy,
        )?;

        let manifest = Self {
            schema: INTEGRITY_MANIFEST_SCHEMA,
            build_id: input.build_id,
            certificate: input.certificate,
            package: input.package,
            dex_files: input.dex_files,
            artifacts: input.artifacts,
            graph,
            topology: ManifestTopology::Canonical,
            distribution,
            response_policy: input.response_policy,
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
        if rebuilt.nodes != self.graph.nodes
            || (self.topology == ManifestTopology::Canonical && rebuilt != self.graph)
        {
            return Err(IntegrityError::InvalidManifest(
                "integrity graph does not match manifest bindings/artifacts".into(),
            ));
        }
        self.graph.validate()?;
        if self.topology == ManifestTopology::CertificateTree {
            validate_tree(&self.graph)?;
        }
        self.distribution.validate(&self.graph)?;
        Ok(())
    }

    /// Replace only the topology; every identity/artifact node remains independently reconstructed.
    /// Every node must remain reachable from the certificate, with one parent and the package first.
    pub fn with_certificate_tree(
        mut self,
        graph: IntegrityGraph,
        distribution: &DistributionConfig,
    ) -> Result<Self> {
        self.validate()?;
        self.graph = graph;
        self.topology = ManifestTopology::CertificateTree;
        self.distribution = DistributionPlan::compile(
            &self.graph,
            &distribution.seed,
            distribution.check_count,
            distribution.redundancy,
        )?;
        self.validate()?;
        Ok(self)
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

fn validate_tree(graph: &IntegrityGraph) -> Result<()> {
    let certificate = graph
        .nodes
        .iter()
        .find(|n| n.kind == IntegrityNodeKind::Certificate)
        .ok_or_else(|| IntegrityError::InvalidGraph("missing tree certificate".into()))?;
    let package = graph
        .nodes
        .iter()
        .find(|n| n.kind == IntegrityNodeKind::Package)
        .ok_or_else(|| IntegrityError::InvalidGraph("missing tree package".into()))?;
    if graph.edges.len() + 1 != graph.nodes.len()
        || !graph
            .edges
            .iter()
            .any(|e| e.from == certificate.id && e.to == package.id)
        || graph
            .edges
            .iter()
            .filter(|e| e.from == certificate.id)
            .count()
            != 1
    {
        return Err(IntegrityError::InvalidGraph(
            "invalid certificate tree topology".into(),
        ));
    }
    Ok(())
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
