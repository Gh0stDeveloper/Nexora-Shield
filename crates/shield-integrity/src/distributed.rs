use crate::error::{IntegrityError, Result};
use crate::graph::IntegrityGraph;
use crate::hash::{hash_components, Sha256Digest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckAssignment {
    pub check_id: u32,
    pub node_ids: Vec<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributionPlan {
    pub seed_fingerprint: Sha256Digest,
    pub redundancy: u8,
    pub checks: Vec<CheckAssignment>,
}

impl DistributionPlan {
    pub fn compile(
        graph: &IntegrityGraph,
        seed: &[u8],
        check_count: u32,
        redundancy: u8,
    ) -> Result<Self> {
        graph.validate()?;
        if seed.is_empty() {
            return Err(IntegrityError::InvalidDistribution(
                "distribution seed must not be empty".into(),
            ));
        }
        if check_count < 2 {
            return Err(IntegrityError::InvalidDistribution(
                "at least two distributed checks are required".into(),
            ));
        }
        if redundancy == 0 || u32::from(redundancy) > check_count {
            return Err(IntegrityError::InvalidDistribution(
                "redundancy must be between 1 and check_count".into(),
            ));
        }

        let seed_fingerprint = hash_components(
            b"NexoraShield:D:distribution-seed:v1",
            [seed],
        );
        let mut assignments = (0..check_count)
            .map(|check_id| CheckAssignment {
                check_id,
                node_ids: Vec::new(),
            })
            .collect::<Vec<_>>();

        for node in &graph.nodes {
            let mut used = BTreeSet::new();
            for replica in 0..redundancy {
                let mut probe = 0_u32;
                let check_id = loop {
                    let replica_bytes = [replica];
                    let probe_bytes = probe.to_le_bytes();
                    let digest = hash_components(
                        b"NexoraShield:D:distributed-check:v1",
                        [
                            seed,
                            node.id.as_bytes().as_slice(),
                            replica_bytes.as_slice(),
                            probe_bytes.as_slice(),
                        ],
                    );
                    let mut raw = [0_u8; 8];
                    raw.copy_from_slice(&digest.as_bytes()[..8]);
                    let candidate = (u64::from_le_bytes(raw) % u64::from(check_count)) as u32;
                    if used.insert(candidate) {
                        break candidate;
                    }
                    probe = probe.checked_add(1).ok_or_else(|| {
                        IntegrityError::InvalidDistribution("assignment probe overflow".into())
                    })?;
                };
                assignments[check_id as usize].node_ids.push(node.id);
            }
        }

        for assignment in &mut assignments {
            assignment.node_ids.sort();
            assignment.node_ids.dedup();
        }

        let plan = Self {
            seed_fingerprint,
            redundancy,
            checks: assignments,
        };
        plan.validate(graph)?;
        Ok(plan)
    }

    pub fn validate(&self, graph: &IntegrityGraph) -> Result<()> {
        if self.checks.len() < 2 || self.redundancy == 0 {
            return Err(IntegrityError::InvalidDistribution(
                "plan must contain multiple checks with positive redundancy".into(),
            ));
        }

        let graph_ids = graph.nodes.iter().map(|node| node.id).collect::<BTreeSet<_>>();
        let mut counts = BTreeMap::<Sha256Digest, u32>::new();
        let mut seen_check_ids = BTreeSet::new();

        for check in &self.checks {
            if !seen_check_ids.insert(check.check_id) {
                return Err(IntegrityError::InvalidDistribution(
                    "duplicate check_id".into(),
                ));
            }
            let unique = check.node_ids.iter().copied().collect::<BTreeSet<_>>();
            if unique.len() != check.node_ids.len() {
                return Err(IntegrityError::InvalidDistribution(format!(
                    "check {} contains duplicate node IDs",
                    check.check_id
                )));
            }
            for node_id in &check.node_ids {
                if !graph_ids.contains(node_id) {
                    return Err(IntegrityError::InvalidDistribution(format!(
                        "check {} references an unknown node",
                        check.check_id
                    )));
                }
                *counts.entry(*node_id).or_default() += 1;
            }
        }

        for node_id in graph_ids {
            if counts.get(&node_id).copied().unwrap_or(0) != u32::from(self.redundancy) {
                return Err(IntegrityError::InvalidDistribution(
                    "every graph node must appear exactly redundancy times".into(),
                ));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn nodes_for_check(&self, check_id: u32) -> Option<&[Sha256Digest]> {
        self.checks
            .iter()
            .find(|check| check.check_id == check_id)
            .map(|check| check.node_ids.as_slice())
    }
}
