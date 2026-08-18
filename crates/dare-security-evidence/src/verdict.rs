//! Bounded verdict vocabulary for a canonical evidence record.
//!
//! Wire values are stable uppercase tokens. There is no implicit default.

use serde::{Deserialize, Serialize};

/// Deterministic security verdict for one evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    /// Observed behavior satisfies the vector's deterministic expectation.
    Pass,
    /// Observed behavior violates the vector's deterministic expectation.
    Fail,
    /// Execution completed but evidence is insufficient to decide deterministically.
    Inconclusive,
    /// The vector could not be evaluated because of an execution/infrastructure failure.
    Error,
}

impl Verdict {
    /// Stable wire token for this verdict.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Inconclusive => "INCONCLUSIVE",
            Self::Error => "ERROR",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Verdict;
    use serde_json::json;

    #[test]
    fn verdict_wire_tokens_are_stable_uppercase() {
        assert_eq!(serde_json::to_value(Verdict::Pass).unwrap(), json!("PASS"));
        assert_eq!(serde_json::to_value(Verdict::Fail).unwrap(), json!("FAIL"));
        assert_eq!(
            serde_json::to_value(Verdict::Inconclusive).unwrap(),
            json!("INCONCLUSIVE")
        );
        assert_eq!(
            serde_json::to_value(Verdict::Error).unwrap(),
            json!("ERROR")
        );
    }

    #[test]
    fn verdict_rejects_unknown_wire_values() {
        let err = serde_json::from_str::<Verdict>("\"UNKNOWN\"").unwrap_err();
        assert!(err.to_string().contains("UNKNOWN") || err.is_data());
    }

    #[test]
    fn verdict_has_no_implicit_default() {
        assert!(serde_json::from_str::<Verdict>("null").is_err());
        assert!(serde_json::from_str::<Verdict>("\"\"").is_err());
        assert!(serde_json::from_str::<Verdict>("\"pass\"").is_err());
    }
}
