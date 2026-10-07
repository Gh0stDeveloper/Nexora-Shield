use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TamperKind {
    RepackedDex,
    RepackedResource,
    ReplacedNativeLibrary,
    ReSignedArtifact,
    ChangedPackageIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TamperObservation {
    pub case_id: String,
    pub kind: TamperKind,
    pub verifier_accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TamperCaseResult {
    pub case_id: String,
    pub kind: TamperKind,
    pub rejected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TamperLabReport {
    pub cases_total: usize,
    pub cases_rejected: usize,
    pub failures: Vec<TamperCaseResult>,
}

impl TamperLabReport {
    #[must_use]
    pub fn passed(&self) -> bool {
        self.failures.is_empty() && self.cases_rejected == self.cases_total
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TamperLab;

impl TamperLab {
    #[must_use]
    pub fn evaluate(observations: &[TamperObservation]) -> TamperLabReport {
        let results = observations
            .iter()
            .map(|observation| TamperCaseResult {
                case_id: observation.case_id.clone(),
                kind: observation.kind,
                rejected: !observation.verifier_accepted,
            })
            .collect::<Vec<_>>();
        let cases_rejected = results.iter().filter(|result| result.rejected).count();
        let failures = results
            .into_iter()
            .filter(|result| !result.rejected)
            .collect();

        TamperLabReport {
            cases_total: observations.len(),
            cases_rejected,
            failures,
        }
    }
}
