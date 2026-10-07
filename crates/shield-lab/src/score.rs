use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityControlResult {
    pub id: String,
    pub weight: u32,
    pub critical: bool,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityScoreReport {
    pub earned_weight: u64,
    pub total_weight: u64,
    pub score_basis_points: u32,
    pub grade: String,
    pub critical_failures: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SecurityScore;

impl SecurityScore {
    #[must_use]
    pub fn calculate(results: &[SecurityControlResult]) -> SecurityScoreReport {
        let total_weight = results
            .iter()
            .map(|result| u64::from(result.weight))
            .sum::<u64>();
        let earned_weight = results
            .iter()
            .filter(|result| result.passed)
            .map(|result| u64::from(result.weight))
            .sum::<u64>();
        let critical_failures = results
            .iter()
            .filter(|result| result.critical && !result.passed)
            .map(|result| result.id.clone())
            .collect::<Vec<_>>();

        let raw_score = if total_weight == 0 {
            0
        } else {
            u32::try_from(
                u128::from(earned_weight)
                    .saturating_mul(10_000)
                    .checked_div(u128::from(total_weight))
                    .unwrap_or(0),
            )
            .unwrap_or(10_000)
        };
        let score_basis_points = if critical_failures.is_empty() {
            raw_score
        } else {
            raw_score.min(5_900)
        };
        let grade = match score_basis_points {
            9_000..=10_000 => "A",
            8_000..=8_999 => "B",
            7_000..=7_999 => "C",
            6_000..=6_999 => "D",
            _ => "F",
        }
        .to_owned();

        SecurityScoreReport {
            earned_weight,
            total_weight,
            score_basis_points,
            grade,
            critical_failures,
        }
    }
}
