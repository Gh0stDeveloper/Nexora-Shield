use nexora_shield_diversity::{
    BuildDiversitySignature, BypassPortabilityReport, CrossBuildBypassRegression,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortabilityGateReport {
    pub report: BypassPortabilityReport,
    pub maximum_transfer_basis_points: u32,
    pub passed: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PortabilityLab;

impl PortabilityLab {
    #[must_use]
    pub fn evaluate(
        signatures: &[BuildDiversitySignature],
        maximum_transfer_basis_points: u32,
    ) -> PortabilityGateReport {
        let report = CrossBuildBypassRegression::evaluate(signatures);
        let passed = report.all_builds_unique()
            && report.within_transfer_budget(maximum_transfer_basis_points);
        PortabilityGateReport {
            report,
            maximum_transfer_basis_points,
            passed,
        }
    }
}
