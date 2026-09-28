//! Feeding a remote run into Cycle 006 coverage (Design RF-16).
//!
//! Every record the engines produced names its property inside the engine's
//! own extension. The records are grouped by property, each group's verdict is
//! aggregated with the same rule as the run (FAIL > ERROR > INCONCLUSIVE >
//! PASS), and the result is an [`ExecutionsDocument`] marked
//! `execution_mode = dynamic`, `evidence_class = DYNAMIC_AUTHORIZED`.
//! `validate coverage --executions remote-coverage.json` consumes it.
//!
//! Nothing here decides a verdict: it only regroups what the engines decided.
//! No property is added and no profile denominator moves.

use std::collections::BTreeMap;

use dare_coverage::{EvidenceClass, ExecutionsDocument, PropertyExecution, SupportedMode};
use dare_security_evidence::{SecurityEvidence, Verdict};

use crate::error::{RemoteError, Result};
use crate::result::{aggregate, RemoteResult};

/// Where each engine's bridge records the property it decided.
const PROPERTY_KEYS: [(&str, &str); 4] = [
    (
        dare_prompt_injection::evidence_bridge::EXTENSION_NAMESPACE,
        "property_id",
    ),
    (
        dare_multi_turn_security::evidence_bridge::EXTENSION_NAMESPACE,
        "property",
    ),
    (
        dare_a2a_security::evidence_bridge::EXTENSION_NAMESPACE,
        "property",
    ),
    (
        dare_mcp_auth_security::evidence_bridge::EXTENSION_NAMESPACE,
        "property",
    ),
];

/// The property a record decides, read from its engine's extension.
fn property_of(record: &SecurityEvidence) -> Option<&str> {
    let extensions = record.extensions.as_ref()?;
    PROPERTY_KEYS
        .iter()
        .find_map(|(namespace, key)| extensions.get(*namespace)?.get(*key)?.as_str())
}

/// The coverage input for one remote run.
pub fn executions_document(
    result: &RemoteResult,
    evidence: &[SecurityEvidence],
) -> Result<ExecutionsDocument> {
    let mut grouped: BTreeMap<&str, (Vec<Verdict>, Vec<String>)> = BTreeMap::new();
    for record in evidence {
        // Fail closed: a record that names no property cannot be attributed.
        let property = property_of(record).ok_or(RemoteError::Serialization(
            "an evidence record names no property",
        ))?;
        let (verdicts, ids) = grouped.entry(property).or_default();
        verdicts.push(record.verdict);
        if !ids.contains(&record.id) {
            ids.push(record.id.clone());
        }
    }
    let executions = grouped
        .into_iter()
        .map(|(property, (verdicts, evidence_ids))| PropertyExecution {
            property_id: property.to_owned(),
            verdict: Some(aggregate(verdicts)),
            evidence_ids,
        })
        .collect();
    Ok(ExecutionsDocument {
        schema_version: ExecutionsDocument::SCHEMA_VERSION.to_owned(),
        execution_mode: SupportedMode::Dynamic,
        evidence_class: EvidenceClass::DynamicAuthorized,
        source: format!(
            "remote run under authorization {} ({}) against {}, capture {}, observed {} to {}",
            result.authorization_id,
            result.authorization_digest,
            result.origin,
            result.capture_id,
            result.observed_window.from,
            result.observed_window.to
        ),
        executions,
    })
}
