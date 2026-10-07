use crate::error::{DiversityError, Result};
use crate::seed::{DiversityDomain, SeedDeriver};
use nexora_shield_integrity::{
    IntegrityEdge, IntegrityGraph, IntegrityNode, IntegrityNodeKind, Sha256Digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityTopologyVariant {
    SeededTree,
    LayeredFanout,
    SeededChain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityTopologyPlan {
    pub variant: IntegrityTopologyVariant,
    pub edges: Vec<IntegrityEdge>,
    pub graph_root: Sha256Digest,
    pub fingerprint: [u8; 32],
}

impl IntegrityTopologyPlan {
    pub fn derive(seed: &SeedDeriver, graph: &IntegrityGraph) -> Result<(Self, IntegrityGraph)> {
        graph
            .validate()
            .map_err(|error| DiversityError::Integrity(error.to_string()))?;

        let certificate = graph
            .nodes
            .iter()
            .find(|node| node.kind == IntegrityNodeKind::Certificate)
            .ok_or(DiversityError::MissingCertificateRoot)?;
        let package = graph
            .nodes
            .iter()
            .find(|node| node.kind == IntegrityNodeKind::Package)
            .ok_or(DiversityError::MissingPackageNode)?;

        let mut remaining = graph
            .nodes
            .iter()
            .filter(|node| node.id != certificate.id && node.id != package.id)
            .cloned()
            .collect::<Vec<_>>();
        remaining.sort_by(|left, right| seeded_node_order(seed, left, right));

        let variant_selector =
            seed.derive_u64(DiversityDomain::IntegrityTopology, b"topology-variant")?;
        let variant = match variant_selector % 3 {
            0 => IntegrityTopologyVariant::SeededTree,
            1 => IntegrityTopologyVariant::LayeredFanout,
            _ => IntegrityTopologyVariant::SeededChain,
        };

        let mut edges = vec![IntegrityEdge {
            from: certificate.id,
            to: package.id,
        }];

        match variant {
            IntegrityTopologyVariant::SeededTree => {
                let mut parents = vec![package.id];
                for node in &remaining {
                    let selector = seed.derive_u64(
                        DiversityDomain::IntegrityTopology,
                        node.label.as_bytes(),
                    )?;
                    let parent = parents[usize::try_from(
                        selector % u64::try_from(parents.len()).unwrap_or(u64::MAX),
                    )
                    .unwrap_or(0)];
                    edges.push(IntegrityEdge {
                        from: parent,
                        to: node.id,
                    });
                    parents.push(node.id);
                }
            }
            IntegrityTopologyVariant::LayeredFanout => {
                for (index, node) in remaining.iter().enumerate() {
                    let parent = if index < 2 {
                        package.id
                    } else {
                        remaining[(index - 2) / 2].id
                    };
                    edges.push(IntegrityEdge {
                        from: parent,
                        to: node.id,
                    });
                }
            }
            IntegrityTopologyVariant::SeededChain => {
                let mut parent = package.id;
                for node in &remaining {
                    edges.push(IntegrityEdge {
                        from: parent,
                        to: node.id,
                    });
                    parent = node.id;
                }
            }
        }

        let diversified = graph
            .with_edges(edges.clone())
            .map_err(|error| DiversityError::Integrity(error.to_string()))?;
        let fingerprint = topology_fingerprint(variant, &edges, diversified.root);

        Ok((
            Self {
                variant,
                edges,
                graph_root: diversified.root,
                fingerprint,
            },
            diversified,
        ))
    }
}

fn seeded_node_order(
    seed: &SeedDeriver,
    left: &IntegrityNode,
    right: &IntegrityNode,
) -> Ordering {
    let left_key = node_key(seed, left);
    let right_key = node_key(seed, right);
    left_key.cmp(&right_key).then_with(|| left.id.cmp(&right.id))
}

fn node_key(seed: &SeedDeriver, node: &IntegrityNode) -> u64 {
    seed.derive_u64(DiversityDomain::IntegrityTopology, node.label.as_bytes())
        .unwrap_or(0)
}

fn topology_fingerprint(
    variant: IntegrityTopologyVariant,
    edges: &[IntegrityEdge],
    root: Sha256Digest,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"nexora-shield/integrity-topology/v1");
    hasher.update([variant_code(variant)]);
    for edge in edges {
        hasher.update(edge.from.as_bytes());
        hasher.update(edge.to.as_bytes());
    }
    hasher.update(root.as_bytes());
    hasher.finalize().into()
}

const fn variant_code(variant: IntegrityTopologyVariant) -> u8 {
    match variant {
        IntegrityTopologyVariant::SeededTree => 1,
        IntegrityTopologyVariant::LayeredFanout => 2,
        IntegrityTopologyVariant::SeededChain => 3,
    }
}
