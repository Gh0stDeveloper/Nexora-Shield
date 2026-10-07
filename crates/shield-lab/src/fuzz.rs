use serde::{Deserialize, Serialize};
use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzReport {
    pub cases_total: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub panics: usize,
}

impl FuzzReport {
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.panics == 0
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FuzzFarm;

impl FuzzFarm {
    pub fn run<F>(seeds: &[Vec<u8>], mutations_per_seed: usize, target: F) -> FuzzReport
    where
        F: Fn(&[u8]) -> std::result::Result<(), String>,
    {
        let mut report = FuzzReport {
            cases_total: 0,
            accepted: 0,
            rejected: 0,
            panics: 0,
        };

        for seed in seeds {
            for mutation_index in 0..mutations_per_seed {
                let mutated = mutate(seed, mutation_index);
                report.cases_total = report.cases_total.saturating_add(1);
                match catch_unwind(AssertUnwindSafe(|| target(&mutated))) {
                    Ok(Ok(())) => report.accepted = report.accepted.saturating_add(1),
                    Ok(Err(_)) => report.rejected = report.rejected.saturating_add(1),
                    Err(_) => report.panics = report.panics.saturating_add(1),
                }
            }
        }

        report
    }
}

fn mutate(seed: &[u8], index: usize) -> Vec<u8> {
    let mut output = seed.to_vec();
    match index % 4 {
        0 => {
            if output.is_empty() {
                output.push(0xA5);
            } else {
                let position = index % output.len();
                output[position] ^= 1_u8 << (index % 8);
            }
        }
        1 => {
            let new_len = if output.is_empty() {
                0
            } else {
                index % output.len()
            };
            output.truncate(new_len);
        }
        2 => {
            output.extend_from_slice(&[
                0x4E,
                0x58,
                u8::try_from(index & 0xFF).unwrap_or(0xFF),
            ]);
        }
        _ => {
            if output.len() > 1 {
                let end = (index % output.len()).max(1);
                output[..=end].reverse();
            }
        }
    }
    output
}
