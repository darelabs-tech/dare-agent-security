//! CoverageStatus is distinct from Cycle 001 Verdict.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageStatus {
    Applicable,
    NotApplicable,
    NotTested,
    OutOfScope,
    Blocked,
}

impl CoverageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Applicable => "APPLICABLE",
            Self::NotApplicable => "NOT_APPLICABLE",
            Self::NotTested => "NOT_TESTED",
            Self::OutOfScope => "OUT_OF_SCOPE",
            Self::Blocked => "BLOCKED",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CoverageStatus;
    use serde_json::json;

    #[test]
    fn wire_tokens_are_stable() {
        assert_eq!(
            serde_json::to_value(CoverageStatus::NotApplicable).unwrap(),
            json!("NOT_APPLICABLE")
        );
        assert_eq!(
            serde_json::to_value(CoverageStatus::Blocked).unwrap(),
            json!("BLOCKED")
        );
    }

    #[test]
    fn rejects_unknown_and_lowercase() {
        assert!(serde_json::from_str::<CoverageStatus>("\"PASS\"").is_err());
        assert!(serde_json::from_str::<CoverageStatus>("\"blocked\"").is_err());
    }
}
