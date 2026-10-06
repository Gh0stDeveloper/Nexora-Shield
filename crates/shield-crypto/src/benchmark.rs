use crate::error::{DataProtectionError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, PartialEq, Eq)]
pub struct ExposureProbe {
    pub label: String,
    pub needle: Vec<u8>,
    pub critical: bool,
}

impl ExposureProbe {
    pub fn new(
        label: impl Into<String>,
        needle: impl Into<Vec<u8>>,
        critical: bool,
    ) -> Result<Self> {
        let label = label.into();
        let needle = needle.into();
        if label.trim().is_empty() {
            return Err(DataProtectionError::InvalidProbe(
                "probe label must not be empty".into(),
            ));
        }
        if needle.is_empty() {
            return Err(DataProtectionError::InvalidProbe(
                "probe needle must not be empty".into(),
            ));
        }
        Ok(Self {
            label,
            needle,
            critical,
        })
    }
}

impl fmt::Debug for ExposureProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExposureProbe")
            .field("label", &self.label)
            .field("needle", &"[REDACTED]")
            .field("needle_len", &self.needle.len())
            .field("critical", &self.critical)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureFinding {
    pub label: String,
    pub critical: bool,
    pub baseline_hits: u64,
    pub protected_hits: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExposureReport {
    pub baseline_bytes: u64,
    pub protected_bytes: u64,
    pub overhead_bytes: i64,
    pub overhead_percent: f64,
    pub total_probes: u64,
    pub exposed_probes: u64,
    pub critical_exposed: u64,
    pub findings: Vec<ExposureFinding>,
}

impl ExposureReport {
    #[must_use]
    pub fn passes(&self, maximum_overhead_percent: f64) -> bool {
        self.critical_exposed == 0 && self.overhead_percent <= maximum_overhead_percent
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ExposureBenchmark;

impl ExposureBenchmark {
    pub fn run(
        baseline: &[u8],
        protected: &[u8],
        probes: &[ExposureProbe],
    ) -> Result<ExposureReport> {
        if probes.is_empty() {
            return Err(DataProtectionError::InvalidProbe(
                "at least one exposure probe is required".into(),
            ));
        }

        let mut findings = Vec::with_capacity(probes.len());
        let mut exposed_probes = 0_u64;
        let mut critical_exposed = 0_u64;

        for probe in probes {
            let baseline_hits = count_occurrences(baseline, &probe.needle);
            let protected_hits = count_occurrences(protected, &probe.needle);
            if protected_hits > 0 {
                exposed_probes += 1;
                if probe.critical {
                    critical_exposed += 1;
                }
            }
            findings.push(ExposureFinding {
                label: probe.label.clone(),
                critical: probe.critical,
                baseline_hits,
                protected_hits,
            });
        }

        let baseline_bytes = len_u64(baseline.len())?;
        let protected_bytes = len_u64(protected.len())?;
        let overhead_bytes = signed_difference(protected_bytes, baseline_bytes);
        let overhead_percent = if baseline_bytes == 0 {
            if protected_bytes == 0 { 0.0 } else { f64::INFINITY }
        } else {
            (overhead_bytes as f64 / baseline_bytes as f64) * 100.0
        };

        Ok(ExposureReport {
            baseline_bytes,
            protected_bytes,
            overhead_bytes,
            overhead_percent,
            total_probes: len_u64(probes.len())?,
            exposed_probes,
            critical_exposed,
            findings,
        })
    }
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> u64 {
    if needle.len() > haystack.len() {
        return 0;
    }
    let count = haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count();
    u64::try_from(count).unwrap_or(u64::MAX)
}

fn len_u64(value: usize) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| DataProtectionError::InvalidProbe("length does not fit u64".into()))
}

fn signed_difference(left: u64, right: u64) -> i64 {
    if left >= right {
        i64::try_from(left - right).unwrap_or(i64::MAX)
    } else {
        -i64::try_from(right - left).unwrap_or(i64::MAX)
    }
}
