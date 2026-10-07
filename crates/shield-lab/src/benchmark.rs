use crate::error::{LabError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkControl {
    SameDevice,
    SameOsImage,
    SameToolchain,
    ResetBetweenColdStarts,
    RetainRawSamples,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComparativeBenchmarkMethodology {
    pub warmup_runs: u32,
    pub measured_runs: u32,
    pub controls: BTreeSet<BenchmarkControl>,
}

impl ComparativeBenchmarkMethodology {
    pub fn validate(&self) -> Result<()> {
        if self.warmup_runs < 2 {
            return Err(LabError::InvalidMethodology(
                "at least two warm-up runs are required".into(),
            ));
        }
        if self.measured_runs < 10 {
            return Err(LabError::InvalidMethodology(
                "at least ten measured runs are required".into(),
            ));
        }

        for required in [
            BenchmarkControl::SameDevice,
            BenchmarkControl::SameOsImage,
            BenchmarkControl::SameToolchain,
            BenchmarkControl::RetainRawSamples,
        ] {
            if !self.controls.contains(&required) {
                return Err(LabError::InvalidMethodology(format!(
                    "required benchmark control is missing: {required:?}"
                )));
            }
        }
        Ok(())
    }
}

impl Default for ComparativeBenchmarkMethodology {
    fn default() -> Self {
        Self {
            warmup_runs: 5,
            measured_runs: 30,
            controls: BTreeSet::from([
                BenchmarkControl::SameDevice,
                BenchmarkControl::SameOsImage,
                BenchmarkControl::SameToolchain,
                BenchmarkControl::ResetBetweenColdStarts,
                BenchmarkControl::RetainRawSamples,
            ]),
        }
    }
}
