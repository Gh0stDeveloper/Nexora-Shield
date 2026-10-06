use crate::artifact::{ArtifactIntegrity, ArtifactKind};
use crate::error::{IntegrityError, Result};
use crate::hash::{hash_components, Sha256Digest};
use crate::identity::{CertificateBinding, PackageBinding};
use crate::region::DexIntegrity;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityNodeKind {
    Certificate,
    Package,
    DexFile,
    DexRegion,
    Resource,
    Native,
}

impl IntegrityNodeKind {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Certificate => b"certificate",
            Self::Package => b"package",
            Self::DexFile => b"dex-file",
            Self::DexRegion => b"dex-region",
            Self::Resource => b"resource",
            Self::Native => b"native",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityNode {
    pub id: Sha256Digest,
    pub kind: IntegrityNodeKind,
    pub label: String,
    pub expected: Sha256Digest,
    pub critical: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IntegrityEdge {
    pub from: Sha256Digest,
    pub to: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityGraph {
    pub nodes: Vec<IntegrityNode>,
    pub edges: Vec<IntegrityEdge>,
    pub root: Sha256Digest,
}

impl IntegrityGraph {
    pub fn build(
        certificate: &CertificateBinding,
        package: &PackageBinding,
        dex_files: &[DexIntegrity],
        artifacts: &[ArtifactIntegrity],
    ) -> Result<Self> {
        let certificate_node = node(
            IntegrityNodeKind::Certificate,
            "signing-certificate",
            certificate.fingerprint(),
            true,
        );
        let package_node = node(
            IntegrityNodeKind::Package,
            &format!("package:{}", package.application_id),
            package.fingerprint(),
            true,
        );

        let mut nodes = vec![certificate_node.clone(), package_node.clone()];
        let mut edges = vec![IntegrityEdge {
            from: certificate_node.id,
            to: package_node.id,
        }];
        let mut seen_labels = BTreeSet::new();
        seen_labels.insert(certificate_node.label.clone());
        seen_labels.insert(package_node.label.clone());

        for dex in dex_files {
            let file_node = node(
                IntegrityNodeKind::DexFile,
                &format!("dex:{}:file", dex.name),
                dex.file_digest,
                true,
            );
            insert_unique(&mut seen_labels, &file_node.label)?;
            edges.push(IntegrityEdge {
                from: package_node.id,
                to: file_node.id,
            });

            for region in &dex.regions {
                let region_node = node(
                    IntegrityNodeKind::DexRegion,
                    &format!("dex:{}:{}", dex.name, region.label),
                    region.digest,
                    true,
                );
                insert_unique(&mut seen_labels, &region_node.label)?;
                edges.push(IntegrityEdge {
                    from: file_node.id,
                    to: region_node.id,
                });
                nodes.push(region_node);
            }
            nodes.push(file_node);
        }

        for artifact in artifacts {
            let kind = match artifact.kind {
                ArtifactKind::Resource => IntegrityNodeKind::Resource,
                ArtifactKind::Native => IntegrityNodeKind::Native,
            };
            let artifact_node = node(
                kind,
                &format!("artifact:{}:{}", kind_text(kind), artifact.path),
                artifact.digest,
                matches!(artifact.kind, ArtifactKind::Native),
            );
            insert_unique(&mut seen_labels, &artifact_node.label)?;
            edges.push(IntegrityEdge {
                from: package_node.id,
                to: artifact_node.id,
            });
            nodes.push(artifact_node);
        }

        nodes.sort_by_key(|entry| entry.id);
        edges.sort();
        validate_graph(&nodes, &edges)?;
        let root = graph_root(&nodes, &edges);
        Ok(Self { nodes, edges, root })
    }

    pub fn validate(&self) -> Result<()> {
        validate_graph(&self.nodes, &self.edges)?;
        let observed = graph_root(&self.nodes, &self.edges);
        if observed != self.root {
            return Err(IntegrityError::InvalidGraph(
                "stored graph root does not match nodes/edges".into(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn node(&self, id: Sha256Digest) -> Option<&IntegrityNode> {
        self.nodes.iter().find(|node| node.id == id)
    }

    #[must_use]
    pub fn by_label(&self, label: &str) -> Option<&IntegrityNode> {
        self.nodes.iter().find(|node| node.label == label)
    }
}

fn node(
    kind: IntegrityNodeKind,
    label: &str,
    expected: Sha256Digest,
    critical: bool,
) -> IntegrityNode {
    let id = hash_components(
        b"NexoraShield:D:integrity-node:v1",
        [kind.label(), label.as_bytes()],
    );
    IntegrityNode {
        id,
        kind,
        label: label.to_owned(),
        expected,
        critical,
    }
}

fn insert_unique(seen: &mut BTreeSet<String>, label: &str) -> Result<()> {
    if seen.insert(label.to_owned()) {
        Ok(())
    } else {
        Err(IntegrityError::InvalidGraph(format!(
            "duplicate integrity node label '{label}'"
        )))
    }
}

fn validate_graph(nodes: &[IntegrityNode], edges: &[IntegrityEdge]) -> Result<()> {
    if nodes.is_empty() {
        return Err(IntegrityError::InvalidGraph("graph has no nodes".into()));
    }
    let ids = nodes.iter().map(|node| node.id).collect::<BTreeSet<_>>();
    if ids.len() != nodes.len() {
        return Err(IntegrityError::InvalidGraph(
            "graph contains duplicate node IDs".into(),
        ));
    }
    let labels = nodes
        .iter()
        .map(|node| node.label.as_str())
        .collect::<BTreeSet<_>>();
    if labels.len() != nodes.len() {
        return Err(IntegrityError::InvalidGraph(
            "graph contains duplicate labels".into(),
        ));
    }
    for edge in edges {
        if edge.from == edge.to || !ids.contains(&edge.from) || !ids.contains(&edge.to) {
            return Err(IntegrityError::InvalidGraph(
                "graph contains invalid/self-referential edge".into(),
            ));
        }
    }

    let incoming = edges.iter().fold(
        BTreeMap::<Sha256Digest, usize>::new(),
        |mut counts, edge| {
            *counts.entry(edge.to).or_default() += 1;
            counts
        },
    );
    let roots = nodes
        .iter()
        .filter(|node| incoming.get(&node.id).copied().unwrap_or(0) == 0)
        .collect::<Vec<_>>();
    if roots.len() != 1 || roots[0].kind != IntegrityNodeKind::Certificate {
        return Err(IntegrityError::InvalidGraph(
            "graph must have exactly one certificate root".into(),
        ));
    }
    Ok(())
}

fn graph_root(nodes: &[IntegrityNode], edges: &[IntegrityEdge]) -> Sha256Digest {
    let mut components = Vec::<Vec<u8>>::new();
    for node in nodes {
        components.push(node.id.as_bytes().to_vec());
        components.push(node.kind.label().to_vec());
        components.push(node.label.as_bytes().to_vec());
        components.push(node.expected.as_bytes().to_vec());
        components.push(vec![u8::from(node.critical)]);
    }
    components.push(b"edges".to_vec());
    for edge in edges {
        components.push(edge.from.as_bytes().to_vec());
        components.push(edge.to.as_bytes().to_vec());
    }
    hash_components(
        b"NexoraShield:D:integrity-graph-root:v1",
        components.iter().map(Vec::as_slice),
    )
}

const fn kind_text(kind: IntegrityNodeKind) -> &'static str {
    match kind {
        IntegrityNodeKind::Certificate => "certificate",
        IntegrityNodeKind::Package => "package",
        IntegrityNodeKind::DexFile => "dex",
        IntegrityNodeKind::DexRegion => "dex-region",
        IntegrityNodeKind::Resource => "resource",
        IntegrityNodeKind::Native => "native",
    }
}
