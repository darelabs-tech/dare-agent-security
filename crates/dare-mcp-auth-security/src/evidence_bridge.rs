//! The Cycle 001 evidence bridge.
//!
//! Cycle 018 emits Cycle 001 `SecurityEvidence` records rather than a parallel
//! evidence format. Everything specific to this cycle lives inside a namespaced
//! extension, so the shared contract stays shared and a consumer that knows
//! nothing about MCP authorization can still read the record.
//!
//! Every record targets the synthetic lab. A Cycle 018 result is evidence about
//! a recorded flow, and filing it against a real target would let a report
//! present it as evidence about a deployment.
//!
//! The last thing this module does before returning a record is run Cycle 001's
//! own secret-safety validator over it. A record is a persistence surface, and
//! the check belongs at the boundary rather than in the caller.

use std::collections::BTreeMap;

use dare_security_evidence::{
    validate_secret_safety, Decision, EvidenceTimestamps, ExpectedOutcome, HashRef,
    ObservationSource, ObservedOutcome, Precondition, RedactionMetadata, RedactionStrategy,
    SchemaRef, SchemaVersion, SecurityEvidence, StandardMapping, TargetRef, VectorRef, Verdict,
};
use serde_json::json;
use time::OffsetDateTime;

use crate::canonical::McpAuthBinding;
use crate::error::{McpAuthSecurityError, Result};
use crate::model::{McpAuthCorpusEntry, McpAuthScenario};
use crate::result::{McpAuthSecurityResult, McpAuthTrialRecord};

pub const EVIDENCE_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/evidence/v1/security-evidence.schema.json";

/// Namespace for everything specific to this cycle.
pub const EXTENSION_NAMESPACE: &str = "dare.mcp-auth-security.v1";

/// The only target a Cycle 018 record may name.
pub const SYNTHETIC_TARGET_ID: &str = "synthetic-mcp-auth-security-lab";

/// The expected result every Cycle 018 vector is measured against.
const INVARIANT_HOLDS: &str = "invariant-holds";

/// A stable identifier for one trial's evidence.
pub fn evidence_id(scenario: &McpAuthScenario, trial_index: u32) -> Result<String> {
    let digest = crate::canonical::digest(&json!({
        "scenario": scenario.id,
        "invariant": scenario.invariant.type_.as_str(),
        "trial": trial_index,
    }))?;
    Ok(format!(
        "mcp-auth-{}-{}",
        scenario.invariant.type_.as_str().to_ascii_lowercase(),
        &digest[7..23]
    ))
}

/// How the observed outcome is described, without restating the verdict twice.
fn observed_description(verdict: Verdict, invariant: &str) -> String {
    match verdict {
        Verdict::Pass => format!("no violation of {invariant} was observed in this trial"),
        Verdict::Fail => format!("a deterministic violation of {invariant} was observed"),
        Verdict::Inconclusive => {
            format!("the evidence required to decide {invariant} was not observed")
        }
        Verdict::Error => format!("the harness could not evaluate {invariant}"),
    }
}

/// Build one evidence record per executed trial.
pub fn build_trial_evidence(
    scenario: &McpAuthScenario,
    entry: Option<&McpAuthCorpusEntry>,
    binding: &McpAuthBinding,
    result: &McpAuthSecurityResult,
    trial_index: usize,
    now: OffsetDateTime,
) -> Result<SecurityEvidence> {
    let trial: &McpAuthTrialRecord = result
        .trials
        .get(trial_index)
        .ok_or_else(|| McpAuthSecurityError::invalid("no such trial"))?;
    let invariant = result.invariant.as_str();

    let notes = json!({
        // The relations the whole cycle rests on, carried in every record so a
        // reader holding one artifact still knows what a verdict means.
        "core_relation": "protocol_metadata != authenticated_identity",
        "presence_rule": "token_presence != token_validity",
        "audience_rule": "valid_token != correct_audience",
        "operation_rule": "correct_audience != authorization_for_final_operation",
        "credential_rule": "inbound_mcp_token != upstream_service_token",
        "replay_rule": "same scenario_id != same authorization semantics",
        "execution_note":
            "Evidence is read from local synthetic fixtures. No authorization server, token \
             endpoint, introspection endpoint, JWKS endpoint, metadata URL, registration \
             endpoint, identity provider, browser, MCP server or upstream API is contacted; no \
             signature is verified; no state change or external egress occurs.",
        "separation_note":
            "Cycle 002 owns the MCP revision and discovery lifecycle; Cycle 003 remains the \
             engine for authorization-to-execution binding; Cycle 015 owns principal, tenant and \
             delegation semantics. This record composes with them and replaces none of them.",
        "bounded_claim_note":
            "Verdicts are scoped to the tested vectors under the recorded conditions and never \
             assert that MCP authentication is secure or that token misuse is impossible.",
    });

    let bound = json!({
        "scenario_digest": binding.scenario_digest,
        "protocol_digest": binding.protocol_digest,
        "resource_digest": binding.resource_digest,
        "authorization_digest": binding.authorization_digest,
        "token_digest": binding.token_digest,
        "flow_digest": binding.flow_digest,
        "scope_digest": binding.scope_digest,
        "registration_digest": binding.registration_digest,
        "credential_digest": binding.credential_digest,
        "identity_digest": binding.identity_digest,
        "final_operation_digest": binding.final_operation_digest,
        "corpus_id": entry.map(|entry| entry.id.clone()),
    });

    let run = json!({
        "invariant": invariant,
        "property": result.property_id.as_str(),
        "surface": result.class.as_str(),
        "protocol_revision": result.protocol_revision,
        "mode": result.mode.as_str(),
        "synthetic": result.synthetic,
        "trial_index": trial.index,
        "coverage_satisfied": trial.coverage_satisfied,
        "violations": trial.violations.len(),
        "event_digests": trial.event_digests,
        "state_changes": result.budget.state_changes,
        "external_egress_bytes": result.budget.external_egress_bytes,
    });

    let mut payload = serde_json::Map::new();
    for group in [bound, run, notes] {
        let serde_json::Value::Object(map) = group else {
            unreachable!("each group is a JSON object literal");
        };
        payload.extend(map);
    }
    let mut extensions = BTreeMap::new();
    extensions.insert(
        EXTENSION_NAMESPACE.to_owned(),
        serde_json::Value::Object(payload),
    );

    let hashes = vec![
        HashRef {
            algorithm: "sha256".to_owned(),
            value: binding.scenario_digest.clone(),
        },
        HashRef {
            algorithm: "sha256".to_owned(),
            value: binding.authorization_digest.clone(),
        },
        HashRef {
            algorithm: "sha256".to_owned(),
            value: binding.token_digest.clone(),
        },
    ];

    let standards = scenario
        .standards
        .iter()
        .map(|reference| StandardMapping {
            organization: reference.source.clone(),
            standard: reference.reference.clone(),
            version: None,
            control: reference.status.clone(),
            // Never a URL: a standards attribution is a reference, not a
            // retrieval target, and this cycle fetches nothing.
            url: None,
        })
        .collect();

    let preconditions = vec![Precondition {
        id: Some("mcp_current_protocol_present".to_owned()),
        description: "the target speaks the current MCP protocol revision".to_owned(),
        satisfied: result.protocol_revision == crate::CURRENT_WIRE_REVISION,
    }];

    let evidence = SecurityEvidence {
        schema: SchemaRef {
            id: EVIDENCE_SCHEMA_ID.to_owned(),
            version: SchemaVersion::V1,
        },
        id: evidence_id(scenario, trial.index)?,
        vector: VectorRef {
            id: result
                .corpus_id
                .clone()
                .unwrap_or_else(|| scenario.id.clone()),
            version: "1".to_owned(),
            name: Some(scenario.title.clone()),
        },
        target: TargetRef {
            // Cycle 018 never targets a production MCP server or a real
            // authorization server.
            type_: "synthetic-agent".to_owned(),
            id: SYNTHETIC_TARGET_ID.to_owned(),
            name: Some("DARE synthetic MCP auth-security lab".to_owned()),
            software: None,
            software_version: None,
            protocol: Some("mcp".to_owned()),
            protocol_version: Some(result.protocol_revision.clone()),
        },
        preconditions,
        operation: None,
        authorization_context: None,
        expected: ExpectedOutcome {
            decision: Some(Decision::Deny),
            result: Some(INVARIANT_HOLDS.to_owned()),
            description: Some(format!("security invariant {invariant} holds")),
        },
        observed: ObservedOutcome {
            decision: Some(match trial.verdict {
                Verdict::Fail => Decision::Allow,
                Verdict::Pass => Decision::Deny,
                _ => Decision::NotApplicable,
            }),
            result: Some(match trial.verdict {
                Verdict::Pass => INVARIANT_HOLDS.to_owned(),
                Verdict::Fail => "invariant-violated".to_owned(),
                Verdict::Inconclusive => "evidence-insufficient".to_owned(),
                Verdict::Error => "harness-error".to_owned(),
            }),
            description: Some(observed_description(trial.verdict, invariant)),
            // Observations come from local fixtures and traces, never a live
            // authorization server or MCP deployment.
            source: ObservationSource::Fixture,
        },
        verdict: trial.verdict,
        // Severity is never inferred from the verdict alone: it is a judgement
        // a consumer makes, and baking one in would make this engine's opinion
        // look like a fact.
        severity: None,
        standards,
        artifacts: Vec::new(),
        hashes,
        redaction: RedactionMetadata {
            applied: true,
            strategy: RedactionStrategy::Mask,
            fields: vec![
                "observed.credential_material".to_owned(),
                "observed.evidence_text".to_owned(),
            ],
        },
        timestamps: EvidenceTimestamps {
            started_at: Some(now),
            observed_at: now,
            recorded_at: now,
        },
        extensions: Some(extensions),
    };

    // Final gate: never return a record that carries a secret. The check lives
    // here rather than in the caller because a record is a persistence surface
    // and the boundary is the right place to enforce it.
    validate_secret_safety(&evidence).map_err(|err| {
        McpAuthSecurityError::refusal(format!("evidence failed secret safety: {err}"))
    })?;

    Ok(evidence)
}

/// Build every evidence record for a run.
pub fn build_evidence(
    scenario: &McpAuthScenario,
    entry: Option<&McpAuthCorpusEntry>,
    binding: &McpAuthBinding,
    result: &McpAuthSecurityResult,
    now: OffsetDateTime,
) -> Result<Vec<SecurityEvidence>> {
    (0..result.trials.len())
        .map(|index| build_trial_evidence(scenario, entry, binding, result, index, now))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::tests::scenario;
    use crate::simulated::SimulatedAdapter;
    use crate::trials::TrialPlan;
    use time::macros::datetime;

    fn evidence() -> Vec<SecurityEvidence> {
        let base = scenario();
        let plan = TrialPlan::from_scenario(&base).expect("plan");
        let result =
            crate::result::run_scenario(&base, None, &SimulatedAdapter::new(), plan).expect("runs");
        build_evidence(
            &base,
            None,
            &crate::canonical::bind(&base).expect("binds"),
            &result,
            datetime!(2026-09-06 12:00 UTC),
        )
        .expect("evidence")
    }

    #[test]
    fn evidence_reuses_the_cycle_001_contract_and_vocabulary() {
        let records = evidence();
        assert!(!records.is_empty());
        for record in &records {
            assert_eq!(record.schema.id, EVIDENCE_SCHEMA_ID);
            assert_eq!(record.observed.source, ObservationSource::Fixture);
        }
    }

    #[test]
    fn every_record_targets_the_synthetic_lab_and_says_so() {
        // Filing against a real target would let a report present a fixture
        // result as evidence about a deployment.
        for record in evidence() {
            assert_eq!(record.target.id, SYNTHETIC_TARGET_ID);
            assert_eq!(record.target.type_, "synthetic-agent");
        }
    }

    #[test]
    fn cycle_018_specifics_live_in_the_namespaced_extension_and_nowhere_else() {
        let record = evidence().remove(0);
        let extensions = record.extensions.expect("extensions");
        assert!(extensions.contains_key(EXTENSION_NAMESPACE));
        assert_eq!(
            extensions.len(),
            1,
            "cycle specifics must not leak outside the namespace"
        );
    }

    #[test]
    fn every_bound_digest_reaches_the_record() {
        let record = evidence().remove(0);
        let payload = record.extensions.expect("extensions")[EXTENSION_NAMESPACE].clone();
        for key in [
            "scenario_digest",
            "protocol_digest",
            "resource_digest",
            "authorization_digest",
            "token_digest",
            "flow_digest",
            "scope_digest",
            "registration_digest",
            "credential_digest",
            "identity_digest",
            "final_operation_digest",
        ] {
            assert!(payload.get(key).is_some(), "{key} is missing");
        }
    }

    #[test]
    fn the_central_relations_are_stated_in_every_record() {
        for record in evidence() {
            let payload = record.extensions.expect("extensions")[EXTENSION_NAMESPACE].clone();
            assert!(payload["core_relation"]
                .as_str()
                .expect("string")
                .contains("!="));
            assert!(payload["credential_rule"]
                .as_str()
                .expect("string")
                .contains("inbound_mcp_token"));
            assert!(payload["replay_rule"]
                .as_str()
                .expect("string")
                .contains("scenario_id"));
        }
    }

    #[test]
    fn the_execution_note_names_what_is_never_contacted() {
        let record = evidence().remove(0);
        let payload = record.extensions.expect("extensions")[EXTENSION_NAMESPACE].clone();
        let note = payload["execution_note"].as_str().expect("string");
        for absent in [
            "authorization server",
            "token endpoint",
            "JWKS",
            "registration endpoint",
            "identity provider",
        ] {
            assert!(note.contains(absent), "the note omits {absent}");
        }
        assert!(note.contains("no signature is verified"));
    }

    #[test]
    fn the_separation_note_names_the_cycles_it_composes_with() {
        let record = evidence().remove(0);
        let payload = record.extensions.expect("extensions")[EXTENSION_NAMESPACE].clone();
        let note = payload["separation_note"].as_str().expect("string");
        for cycle in ["Cycle 002", "Cycle 003", "Cycle 015"] {
            assert!(note.contains(cycle), "the note omits {cycle}");
        }
    }

    #[test]
    fn severity_is_never_inferred_from_the_verdict() {
        for record in evidence() {
            assert!(record.severity.is_none());
        }
    }

    #[test]
    fn a_standards_attribution_never_carries_a_retrieval_target() {
        for record in evidence() {
            for mapping in &record.standards {
                assert!(mapping.url.is_none(), "a standards mapping named a URL");
            }
        }
    }

    #[test]
    fn evidence_ids_are_stable_and_move_when_the_invariant_moves() {
        let base = scenario();
        assert_eq!(
            evidence_id(&base, 0).expect("id"),
            evidence_id(&base, 0).expect("id")
        );
        assert_ne!(
            evidence_id(&base, 0).expect("id"),
            evidence_id(&base, 1).expect("id")
        );

        let mut other = base.clone();
        other.invariant.type_ = crate::model::McpAuthInvariantType::PkceBindingPreserved;
        assert_ne!(
            evidence_id(&base, 0).expect("id"),
            evidence_id(&other, 0).expect("id")
        );
    }

    #[test]
    fn an_undecided_trial_carries_no_decision_in_either_direction() {
        // NotApplicable rather than allow or deny: a run that could not decide
        // has not observed a permit and has not observed a refusal.
        let mut quiet = scenario();
        quiet.lab = Some(crate::model::McpAuthLabSpec {
            reference_behavior: crate::model::ReferenceBehavior::NoRelevantObservation,
        });
        quiet.tokens = Default::default();
        quiet.authorization = Default::default();
        quiet.flow = Default::default();
        quiet.scope = Default::default();
        quiet.registration = None;
        quiet.credentials = Default::default();
        quiet.identity_metadata = Default::default();
        quiet.final_operation = Default::default();
        quiet.protected_resource.metadata = None;
        quiet.protected_resource.authorization_servers = vec![];

        let plan = TrialPlan::from_scenario(&quiet).expect("plan");
        let result = crate::result::run_scenario(&quiet, None, &SimulatedAdapter::new(), plan)
            .expect("runs");
        let records = build_evidence(
            &quiet,
            None,
            &crate::canonical::bind(&quiet).expect("binds"),
            &result,
            datetime!(2026-09-06 12:00 UTC),
        )
        .expect("evidence");
        for record in records {
            assert_eq!(record.verdict, Verdict::Inconclusive);
            assert_eq!(record.observed.decision, Some(Decision::NotApplicable));
        }
    }

    /// Whether the sentence leading up to an occurrence negates it.
    ///
    /// A substring ban cannot separate "token misuse is impossible" from "never
    /// assert that token misuse is impossible" — they share their trailing
    /// words. The claim is what matters, so the check looks at whether the
    /// sentence the phrase sits in denies it.
    fn sentence_denies(prefix: &str) -> bool {
        let start = prefix
            .rfind(['.', ';', '!', '?'])
            .map(|index| index + 1)
            .unwrap_or(0);
        let sentence = &prefix[start..];
        ["not ", "no ", "never ", "cannot ", "nor ", "nothing "]
            .iter()
            .any(|marker| sentence.contains(marker))
    }

    #[test]
    fn no_record_claims_conformance_or_universal_safety() {
        // Anchored on the claim rather than the vocabulary. Every record has to
        // be able to say "never assert ... that token misuse is impossible",
        // and a check that fired on those words would ban the sentence
        // documenting the boundary — which is the check the next author
        // deletes.
        for record in evidence() {
            let rendered = serde_json::to_string(&record)
                .expect("serializes")
                .to_lowercase();
            for phrase in [
                "mcp compliant",
                "is certified",
                "fully protected",
                "impossible",
                "authentication is secure",
                "guaranteed secure",
            ] {
                let mut from = 0usize;
                while let Some(offset) = rendered[from..].find(phrase) {
                    let index = from + offset;
                    assert!(
                        sentence_denies(&rendered[..index]),
                        "a record affirmatively claimed `{phrase}`"
                    );
                    from = index + phrase.len();
                }
            }
        }
    }

    #[test]
    fn every_record_denies_the_universal_claim_rather_than_omitting_it() {
        // The mirror of the test above. Omitting the disclaimer would pass a
        // ban-list check trivially; the note has to actually be there, because
        // a reader holding one record has no other way to learn the limit.
        for record in evidence() {
            let payload = record.extensions.expect("extensions")[EXTENSION_NAMESPACE].clone();
            let note = payload["bounded_claim_note"].as_str().expect("string");
            assert!(note.contains("never assert"));
            assert!(note.contains("impossible"));
        }
    }
}
