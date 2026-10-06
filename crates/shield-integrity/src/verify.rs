use crate::artifact::{ArtifactIntegrity, ArtifactKind};
use crate::error::{IntegrityError, Result};
use crate::graph::{IntegrityNode, IntegrityNodeKind};
use crate::hash::Sha256Digest;
use crate::identity::{CertificateObservation, PackageObservation};
use crate::manifest::IntegrityManifest;
use crate::response::{IntegrityResponse, IntegritySeverity};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityEvidence {
    pub certificate: CertificateObservation,
    pub package: PackageObservation,
    pub dex_files: BTreeMap<String, Vec<u8>>,
    pub artifacts: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityFailureKind {
    Certificate,
    Package,
    MissingDex,
    DexFile,
    DexRegion,
    MissingArtifact,
    Resource,
    Native,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityFailure {
    pub node_id: Sha256Digest,
    pub label: String,
    pub kind: IntegrityFailureKind,
    pub severity: IntegritySeverity,
    pub expected: Sha256Digest,
    pub observed: Option<Sha256Digest>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityVerdict {
    pub clean: bool,
    pub severity: IntegritySeverity,
    pub response: IntegrityResponse,
    pub checks_total: usize,
    pub checks_passed: usize,
    pub failures: Vec<IntegrityFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeResult {
    matched: bool,
    observed: Option<Sha256Digest>,
    reason: String,
}

pub struct IntegrityVerifier;

impl IntegrityVerifier {
    pub fn verify_all(
        manifest: &IntegrityManifest,
        evidence: &IntegrityEvidence,
    ) -> Result<IntegrityVerdict> {
        manifest.validate()?;
        let results = collect_results(manifest, evidence)?;
        verdict_for_nodes(
            manifest,
            manifest.graph.nodes.iter().map(|node| node.id),
            &results,
        )
    }

    pub fn verify_check(
        manifest: &IntegrityManifest,
        evidence: &IntegrityEvidence,
        check_id: u32,
    ) -> Result<IntegrityVerdict> {
        manifest.validate()?;
        let node_ids = manifest
            .distribution
            .nodes_for_check(check_id)
            .ok_or_else(|| {
                IntegrityError::InvalidDistribution(format!("unknown check_id {check_id}"))
            })?;
        let results = collect_results(manifest, evidence)?;
        verdict_for_nodes(manifest, node_ids.iter().copied(), &results)
    }
}

fn collect_results(
    manifest: &IntegrityManifest,
    evidence: &IntegrityEvidence,
) -> Result<BTreeMap<Sha256Digest, NodeResult>> {
    let mut results = BTreeMap::new();

    let certificate_node = manifest
        .graph
        .by_label("signing-certificate")
        .ok_or_else(|| IntegrityError::InvalidGraph("certificate node is missing".into()))?;
    let certificate = manifest.certificate.verify(&evidence.certificate);
    results.insert(
        certificate_node.id,
        NodeResult {
            matched: certificate.matched,
            observed: Some(if certificate.matched {
                certificate_node.expected
            } else {
                certificate.observed_fingerprint
            }),
            reason: certificate.reason,
        },
    );

    let package_label = format!("package:{}", manifest.package.application_id);
    let package_node = manifest
        .graph
        .by_label(&package_label)
        .ok_or_else(|| IntegrityError::InvalidGraph("package node is missing".into()))?;
    let package = manifest.package.verify(&evidence.package);
    results.insert(
        package_node.id,
        NodeResult {
            matched: package.matched,
            observed: Some(package.observed_fingerprint),
            reason: package.reason,
        },
    );

    for dex in &manifest.dex_files {
        let file_label = format!("dex:{}:file", dex.name);
        let file_node = manifest
            .graph
            .by_label(&file_label)
            .ok_or_else(|| IntegrityError::InvalidGraph(format!("missing node '{file_label}'")))?;

        let Some(bytes) = evidence.dex_files.get(&dex.name) else {
            results.insert(
                file_node.id,
                NodeResult {
                    matched: false,
                    observed: None,
                    reason: "DEX evidence is missing".into(),
                },
            );
            for region in &dex.regions {
                let label = format!("dex:{}:{}", dex.name, region.label);
                let node = manifest.graph.by_label(&label).ok_or_else(|| {
                    IntegrityError::InvalidGraph(format!("missing node '{label}'"))
                })?;
                results.insert(
                    node.id,
                    NodeResult {
                        matched: false,
                        observed: None,
                        reason: "DEX evidence is missing".into(),
                    },
                );
            }
            continue;
        };

        let checks = dex.verify(bytes)?;
        for check in checks {
            let label = if check.label == "file" {
                file_label.clone()
            } else {
                format!("dex:{}:{}", dex.name, check.label)
            };
            let node = manifest
                .graph
                .by_label(&label)
                .ok_or_else(|| IntegrityError::InvalidGraph(format!("missing node '{label}'")))?;
            results.insert(
                node.id,
                NodeResult {
                    matched: check.matched,
                    observed: Some(check.observed),
                    reason: if check.matched {
                        "DEX digest matches".into()
                    } else {
                        "DEX digest mismatch".into()
                    },
                },
            );
        }
    }

    for artifact in &manifest.artifacts {
        collect_artifact_result(manifest, evidence, artifact, &mut results)?;
    }

    if results.len() != manifest.graph.nodes.len() {
        let known = results.keys().copied().collect::<BTreeSet<_>>();
        let missing = manifest
            .graph
            .nodes
            .iter()
            .filter(|node| !known.contains(&node.id))
            .map(|node| node.label.clone())
            .collect::<Vec<_>>();
        return Err(IntegrityError::MissingEvidence(format!(
            "no verifier result for nodes: {}",
            missing.join(", ")
        )));
    }

    Ok(results)
}

fn collect_artifact_result(
    manifest: &IntegrityManifest,
    evidence: &IntegrityEvidence,
    artifact: &ArtifactIntegrity,
    results: &mut BTreeMap<Sha256Digest, NodeResult>,
) -> Result<()> {
    let kind_text = match artifact.kind {
        ArtifactKind::Resource => "resource",
        ArtifactKind::Native => "native",
    };
    let label = format!("artifact:{kind_text}:{}", artifact.path);
    let node = manifest
        .graph
        .by_label(&label)
        .ok_or_else(|| IntegrityError::InvalidGraph(format!("missing node '{label}'")))?;

    let Some(bytes) = evidence.artifacts.get(&artifact.path) else {
        results.insert(
            node.id,
            NodeResult {
                matched: false,
                observed: None,
                reason: "artifact evidence is missing".into(),
            },
        );
        return Ok(());
    };

    let check = artifact.verify(bytes)?;
    results.insert(
        node.id,
        NodeResult {
            matched: check.matched,
            observed: Some(check.observed),
            reason: if check.matched {
                "artifact digest matches".into()
            } else {
                "artifact digest mismatch".into()
            },
        },
    );
    Ok(())
}

fn verdict_for_nodes(
    manifest: &IntegrityManifest,
    node_ids: impl IntoIterator<Item = Sha256Digest>,
    results: &BTreeMap<Sha256Digest, NodeResult>,
) -> Result<IntegrityVerdict> {
    let mut failures = Vec::new();
    let mut checks_total = 0_usize;
    let mut checks_passed = 0_usize;
    let mut severity = IntegritySeverity::Info;

    for node_id in node_ids {
        checks_total = checks_total.saturating_add(1);
        let node = manifest
            .graph
            .node(node_id)
            .ok_or_else(|| IntegrityError::InvalidGraph("assigned node does not exist".into()))?;
        let result = results.get(&node_id).ok_or_else(|| {
            IntegrityError::MissingEvidence(format!("missing result for '{}'", node.label))
        })?;

        if result.matched {
            checks_passed = checks_passed.saturating_add(1);
            continue;
        }

        let failure_severity = severity_for(node);
        severity = severity.max(failure_severity);
        failures.push(IntegrityFailure {
            node_id,
            label: node.label.clone(),
            kind: failure_kind(node, result.observed.is_none()),
            severity: failure_severity,
            expected: node.expected,
            observed: result.observed,
            reason: result.reason.clone(),
        });
    }

    let response = manifest.response_policy.response_for(severity);
    Ok(IntegrityVerdict {
        clean: failures.is_empty(),
        severity,
        response,
        checks_total,
        checks_passed,
        failures,
    })
}

const fn severity_for(node: &IntegrityNode) -> IntegritySeverity {
    match node.kind {
        IntegrityNodeKind::Certificate | IntegrityNodeKind::Package | IntegrityNodeKind::Native => {
            IntegritySeverity::Critical
        }
        IntegrityNodeKind::DexFile | IntegrityNodeKind::DexRegion => IntegritySeverity::Critical,
        IntegrityNodeKind::Resource => {
            if node.critical {
                IntegritySeverity::Critical
            } else {
                IntegritySeverity::High
            }
        }
    }
}

const fn failure_kind(node: &IntegrityNode, missing: bool) -> IntegrityFailureKind {
    match node.kind {
        IntegrityNodeKind::Certificate => IntegrityFailureKind::Certificate,
        IntegrityNodeKind::Package => IntegrityFailureKind::Package,
        IntegrityNodeKind::DexFile => {
            if missing {
                IntegrityFailureKind::MissingDex
            } else {
                IntegrityFailureKind::DexFile
            }
        }
        IntegrityNodeKind::DexRegion => {
            if missing {
                IntegrityFailureKind::MissingDex
            } else {
                IntegrityFailureKind::DexRegion
            }
        }
        IntegrityNodeKind::Resource => {
            if missing {
                IntegrityFailureKind::MissingArtifact
            } else {
                IntegrityFailureKind::Resource
            }
        }
        IntegrityNodeKind::Native => {
            if missing {
                IntegrityFailureKind::MissingArtifact
            } else {
                IntegrityFailureKind::Native
            }
        }
    }
}
