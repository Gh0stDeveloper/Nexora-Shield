use crate::error::{LabError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceSample {
    pub label: String,
    pub baseline_micros: u64,
    pub protected_micros: u64,
    pub baseline_bytes: u64,
    pub protected_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceBudget {
    pub maximum_runtime_overhead_basis_points: u32,
    pub maximum_size_overhead_basis_points: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceReport {
    pub samples: usize,
    pub maximum_runtime_overhead_basis_points: u32,
    pub maximum_size_overhead_basis_points: u32,
    pub p95_protected_micros: u64,
    pub passed: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PerformanceFarm;

impl PerformanceFarm {
    pub fn evaluate(
        samples: &[PerformanceSample],
        budget: PerformanceBudget,
    ) -> Result<PerformanceReport> {
        if samples.is_empty() {
            return Err(LabError::InvalidPerformanceSample(
                "at least one performance sample is required".into(),
            ));
        }

        let mut runtime_overheads = Vec::with_capacity(samples.len());
        let mut size_overheads = Vec::with_capacity(samples.len());
        let mut protected_times = Vec::with_capacity(samples.len());

        for sample in samples {
            if sample.baseline_micros == 0 || sample.baseline_bytes == 0 {
                return Err(LabError::InvalidPerformanceSample(format!(
                    "'{}' has a zero baseline",
                    sample.label
                )));
            }
            runtime_overheads.push(overhead_basis_points(
                sample.baseline_micros,
                sample.protected_micros,
            ));
            size_overheads.push(overhead_basis_points(
                sample.baseline_bytes,
                sample.protected_bytes,
            ));
            protected_times.push(sample.protected_micros);
        }

        protected_times.sort_unstable();
        let rank = protected_times.len().saturating_mul(95).saturating_add(99) / 100;
        let p95_index = rank.saturating_sub(1).min(protected_times.len() - 1);
        let maximum_runtime_overhead_basis_points =
            runtime_overheads.into_iter().max().unwrap_or(0);
        let maximum_size_overhead_basis_points = size_overheads.into_iter().max().unwrap_or(0);
        let passed = maximum_runtime_overhead_basis_points
            <= budget.maximum_runtime_overhead_basis_points
            && maximum_size_overhead_basis_points <= budget.maximum_size_overhead_basis_points;

        Ok(PerformanceReport {
            samples: samples.len(),
            maximum_runtime_overhead_basis_points,
            maximum_size_overhead_basis_points,
            p95_protected_micros: protected_times[p95_index],
            passed,
        })
    }
}

fn overhead_basis_points(baseline: u64, protected: u64) -> u32 {
    if protected <= baseline {
        return 0;
    }
    let delta = protected.saturating_sub(baseline);
    let basis_points = u128::from(delta)
        .saturating_mul(10_000)
        .checked_div(u128::from(baseline))
        .unwrap_or(u128::from(u32::MAX));
    u32::try_from(basis_points).unwrap_or(u32::MAX)
}
