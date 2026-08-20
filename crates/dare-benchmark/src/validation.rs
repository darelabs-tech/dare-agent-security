//! Human-validation ledger (positive / negative / ambiguous streams).

use serde::{Deserialize, Serialize};

use crate::error::BenchmarkError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationStream {
    PositiveFailReview,
    NegativePassReview,
    AmbiguousGapReview,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HumanValidationEntry {
    pub sample_id: String,
    pub target_id: String,
    pub property_id: Option<String>,
    pub stream: ValidationStream,
    pub machine_verdict: Option<String>,
    pub human_label: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct HumanValidationLedger {
    pub entries: Vec<HumanValidationEntry>,
}

pub fn append_validation_entry(
    ledger: &mut HumanValidationLedger,
    entry: HumanValidationEntry,
) -> Result<(), BenchmarkError> {
    if entry.sample_id.is_empty() || entry.target_id.is_empty() || entry.human_label.is_empty() {
        return Err(BenchmarkError::InvalidState(
            "validation entry requires sample_id, target_id, human_label".to_owned(),
        ));
    }
    // Machine evidence is not mutated — ledger is append-only metadata.
    ledger.entries.push(entry);
    Ok(())
}

impl HumanValidationLedger {
    pub fn count_stream(&self, stream: ValidationStream) -> usize {
        self.entries.iter().filter(|e| e.stream == stream).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_covers_positive_and_negative_streams() {
        let mut ledger = HumanValidationLedger::default();
        append_validation_entry(
            &mut ledger,
            HumanValidationEntry {
                sample_id: "s1".to_owned(),
                target_id: "mcp-target-000001".to_owned(),
                property_id: Some("MCP.AUTHZ.PER_OPERATION".to_owned()),
                stream: ValidationStream::PositiveFailReview,
                machine_verdict: Some("FAIL".to_owned()),
                human_label: "true_positive".to_owned(),
                notes: None,
            },
        )
        .unwrap();
        append_validation_entry(
            &mut ledger,
            HumanValidationEntry {
                sample_id: "s2".to_owned(),
                target_id: "mcp-target-000002".to_owned(),
                property_id: None,
                stream: ValidationStream::NegativePassReview,
                machine_verdict: Some("PASS".to_owned()),
                human_label: "possible_miss".to_owned(),
                notes: Some("spot check".to_owned()),
            },
        )
        .unwrap();
        assert_eq!(ledger.count_stream(ValidationStream::PositiveFailReview), 1);
        assert_eq!(ledger.count_stream(ValidationStream::NegativePassReview), 1);
    }
}
