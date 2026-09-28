//! Evidence re-tagging (BLUEPRINT AD-14).
//!
//! The engines build their evidence unchanged. Each record is then marked as
//! a protocol response and given its provenance under
//! `extensions["dare.remote"]`, and re-validated. A record that fails
//! validation is never returned.

use std::collections::{BTreeMap, BTreeSet};

use dare_security_evidence::{
    validate, validate_secret_safety, ObservationSource, SecurityEvidence,
};
use serde::Serialize;
use serde_json::Value;

use crate::error::{RemoteError, Result};

/// Where a live record came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Provenance {
    pub authorization_id: String,
    pub authorization_digest: String,
    pub plan_digest: String,
    pub origin: String,
    pub capture_id: String,
    pub capture_digest: String,
    pub observed_window: ObservedWindow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedWindow {
    pub from: String,
    pub to: String,
}

pub const EXTENSION: &str = "dare.remote";

/// Lower a PASS record to INCONCLUSIVE: the engine decided PASS over fields
/// the protocol cannot carry, so the record may not claim the invariant held.
/// Decision and result are cleared, as for any INCONCLUSIVE record.
pub fn downgrade_pass(mut evidence: SecurityEvidence, why: &str) -> Result<SecurityEvidence> {
    if evidence.verdict == dare_security_evidence::Verdict::Pass {
        evidence.verdict = dare_security_evidence::Verdict::Inconclusive;
        evidence.observed.decision = None;
        evidence.observed.result = None;
        evidence.observed.description = Some(why.chars().take(512).collect());
    }
    validate(&evidence)
        .map_err(|_| RemoteError::Serialization("downgraded evidence failed validation"))?;
    Ok(evidence)
}

/// Re-tag one engine record for a live run.
pub fn retag(
    mut evidence: SecurityEvidence,
    provenance: &Provenance,
    self_reported: &BTreeSet<&'static str>,
    not_observable: &[&'static str],
) -> Result<SecurityEvidence> {
    evidence.observed.source = ObservationSource::ProtocolResponse;
    let mut extension =
        serde_json::to_value(provenance).map_err(|_| RemoteError::Serialization("provenance"))?;
    if let Value::Object(map) = &mut extension {
        map.insert(
            "self_reported_fields".into(),
            Value::from(self_reported.iter().copied().collect::<Vec<_>>()),
        );
        map.insert(
            "not_observable".into(),
            Value::from(not_observable.to_vec()),
        );
    }
    evidence
        .extensions
        .get_or_insert_with(BTreeMap::new)
        .insert(EXTENSION.to_owned(), extension);
    validate(&evidence)
        .map_err(|_| RemoteError::Serialization("re-tagged evidence failed validation"))?;
    validate_secret_safety(&evidence)
        .map_err(|_| RemoteError::Serialization("re-tagged evidence failed the secret check"))?;
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> Provenance {
        Provenance {
            authorization_id: "lab-auth-1".into(),
            authorization_digest: crate::plan::tests::D1.into(),
            plan_digest: crate::plan::tests::D2.into(),
            origin: "https://127.0.0.1:18443".into(),
            capture_id: "cap-0123456789abcdef".into(),
            capture_digest: crate::plan::tests::D1.into(),
            observed_window: ObservedWindow {
                from: "2026-09-28T12:00:00Z".into(),
                to: "2026-09-28T12:00:02Z".into(),
            },
        }
    }

    /// A real record from the prompt-injection engine's simulated lab.
    fn engine_record() -> SecurityEvidence {
        use dare_prompt_injection::simulated::SimulatedAdapter;
        let sources = crate::engines::Sources {
            root: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."),
        };
        let loaded = crate::engines::prompt_injection::load(&sources, "PI-LAB-001").unwrap();
        let adapter = SimulatedAdapter::new(loaded.scenario.lab.as_ref().unwrap().profile());
        let plan =
            dare_prompt_injection::trials::TrialPlan::from_scenario(&loaded.scenario).unwrap();
        let result = dare_prompt_injection::result::run_scenario(
            &loaded.scenario,
            &loaded.entry,
            &adapter,
            plan,
        )
        .unwrap();
        let binding =
            dare_prompt_injection::canonical::bind(&loaded.scenario, &loaded.entry).unwrap();
        let now = time::OffsetDateTime::UNIX_EPOCH;
        dare_prompt_injection::evidence_bridge::build_evidence(
            &loaded.scenario,
            &loaded.entry,
            &binding,
            &result,
            now,
        )
        .unwrap()
        .remove(0)
    }

    #[test]
    fn a_retagged_record_is_a_protocol_response_with_provenance_and_still_valid() {
        let record = engine_record();
        let fields: BTreeSet<&'static str> = ["refusal"].into();
        let out = retag(record, &provenance(), &fields, &["actions"]).unwrap();
        assert_eq!(out.observed.source, ObservationSource::ProtocolResponse);
        let ext = &out.extensions.as_ref().unwrap()[EXTENSION];
        assert_eq!(ext["origin"], "https://127.0.0.1:18443");
        assert_eq!(ext["self_reported_fields"][0], "refusal");
        assert_eq!(ext["not_observable"][0], "actions");
        validate(&out).unwrap();
    }
}
