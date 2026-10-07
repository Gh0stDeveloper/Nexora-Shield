use crate::error::{LabError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComparativeBenchmarkMethodology {
    pub warmup_runs: u32,
    pub measured_runs: u32,
    pub same_device: bool,
    pub same_os_image: bool,
    pub same_toolchain: bool,
    pub reset_between_cold_starts: bool,
    pub retain_raw_samples: bool,
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
        if !(self.same_device && self.same_os_image && self.same_toolchain) {
            return Err(LabError::InvalidMethodology(
                "baseline and protected runs must use the same device, OS image and toolchain"
                    .into(),
            ));
        }
        if !self.retain_raw_samples {
            return Err(LabError::InvalidMethodology(
                "raw benchmark samples must be retained".into(),
            ));
        }
        Ok(())
    }
}

impl Default for ComparativeBenchmarkMethodology {
    fn default() -> Self {
        Self {
            warmup_runs: 5,
            measured_runs: 30,
            same_device: true,
            same_os_image: true,
            same_toolchain: true,
            reset_between_cold_starts: true,
            retain_raw_samples: true,
        }
    }
}
