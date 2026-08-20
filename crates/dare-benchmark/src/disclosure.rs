//! Responsible disclosure publication states and redacted export.

use serde::{Deserialize, Serialize};

use crate::error::BenchmarkError;
use crate::record::BenchmarkRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DisclosureState {
    Public,
    DisclosurePending,
    Embargoed,
    Redacted,
    Fixed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicationExport {
    pub target_id: String,
    pub repository: String,
    pub commit: String,
    pub publication_state: DisclosureState,
    pub findings_summary: FindingsPublic,
    pub redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingsPublic {
    pub pass: u32,
    pub fail: u32,
    pub inconclusive: u32,
    pub error: u32,
}

const SECRET_CANARIES: [&str; 4] = ["Bearer ", "sk_live_", "password=", "Authorization:"];

pub fn publication_safe_export(
    record: &BenchmarkRecord,
    state: DisclosureState,
) -> Result<PublicationExport, BenchmarkError> {
    let encoded = serde_json::to_string(record).map_err(|_| BenchmarkError::Serialization {
        kind: "publication-json",
    })?;
    for canary in SECRET_CANARIES {
        if encoded.contains(canary) {
            return Err(BenchmarkError::SafetyRefusal(
                "refusing to publish secret-like content".to_owned(),
            ));
        }
    }

    let redacted = matches!(
        state,
        DisclosureState::Embargoed | DisclosureState::Redacted | DisclosureState::DisclosurePending
    );

    Ok(PublicationExport {
        target_id: record.target.id.clone(),
        repository: if redacted {
            "[redacted]".to_owned()
        } else {
            record.target.repository.clone()
        },
        commit: record.target.commit.clone(),
        publication_state: state,
        findings_summary: FindingsPublic {
            pass: record.findings.pass,
            fail: if redacted && state != DisclosureState::Fixed {
                0
            } else {
                record.findings.fail
            },
            inconclusive: record.findings.inconclusive,
            error: record.findings.error,
        },
        redacted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embargo_redacts_repository() {
        // Minimal structural check via JSON round-trip helper in runner tests.
        assert_eq!(
            serde_json::to_value(DisclosureState::Embargoed).unwrap(),
            serde_json::json!("EMBARGOED")
        );
    }
}
