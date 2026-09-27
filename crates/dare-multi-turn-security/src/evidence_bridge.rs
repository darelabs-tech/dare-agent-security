//! One Cycle 001 `SecurityEvidence` record per invariant.
//!
//! The record carries identifiers, digests and closed classes only: the path
//! (node ids and observation classes), the deciding turn references, the
//! graph digests and the final chain digests. No turn content, no target
//! output and no canary marker is ever copied in, and every record is checked
//! with `validate_secret_safety` before it is returned.

use std::collections::BTreeMap;

use dare_security_evidence::{
    validate_secret_safety, Decision, EvidenceTimestamps, ExpectedOutcome, HashRef,
    ObservationSource, ObservedOutcome, Precondition, RedactionMetadata, RedactionStrategy,
    SchemaRef, SchemaVersion, SecurityEvidence, StandardMapping, TargetRef, VectorRef, Verdict,
};
use serde_json::json;
use time::OffsetDateTime;

use crate::canonical::digest;
use crate::error::{MultiTurnError, Result};
use crate::invariant::InvariantOutcome;
use crate::local_synthetic::SYNTHETIC_TARGET_ID;
use crate::model::HarnessMode;
use crate::result::MultiTurnResult;

pub const EVIDENCE_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/evidence/v1/security-evidence.schema.json";
pub const EXTENSION_NAMESPACE: &str = "dare.multi-turn-security.v1";

const INVARIANT_HOLDS: &str = "invariant-holds";

fn asi_for(property: &str) -> &'static str {
    match property.split('.').nth(1) {
        Some("IDENTITY") => "ASI03",
        Some("MEMORY") => "ASI06",
        Some("HUMAN_APPROVAL") => "ASI09",
        _ => "ASI01",
    }
}

/// Cycle 001 hash values are bare lowercase hex; the algorithm is its own field.
fn bare_hash(digest: &str) -> HashRef {
    HashRef {
        algorithm: "sha256".to_owned(),
        value: digest.trim_start_matches("sha256:").to_owned(),
    }
}

pub fn evidence_id(result: &MultiTurnResult, outcome: &InvariantOutcome) -> Result<String> {
    let d = digest(
        &json!({ "scenario": result.scenario_id, "invariant": outcome.invariant.as_str() }),
    )?;
    Ok(format!(
        "multi-turn-{}-{}",
        outcome
            .invariant
            .as_str()
            .to_ascii_lowercase()
            .replace('_', "-"),
        &d[7..23]
    ))
}

fn build_one(
    result: &MultiTurnResult,
    outcome: &InvariantOutcome,
    now: OffsetDateTime,
) -> Result<SecurityEvidence> {
    let invariant = outcome.invariant.as_str();
    let mut payload = serde_json::Map::new();
    payload.insert("invariant".into(), json!(invariant));
    payload.insert("property".into(), json!(outcome.property_id));
    payload.insert("reason".into(), json!(outcome.reason));
    payload.insert("applicable".into(), json!(outcome.applicable));
    payload.insert("mode".into(), json!(result.mode));
    payload.insert("synthetic".into(), json!(result.synthetic));
    payload.insert("deciding_turns".into(), json!(outcome.deciding_turns));
    payload.insert(
        "conversations".into(),
        json!(result
            .conversations
            .iter()
            .map(|c| json!({ "conversation_id": c.conversation_id, "stop": c.stop, "path": c.path, "unreached_nodes": c.unreached_nodes }))
            .collect::<Vec<_>>()),
    );
    payload.insert("state_changes".into(), json!(result.budget.state_changes));
    payload.insert(
        "external_egress_bytes".into(),
        json!(result.budget.egress_bytes),
    );
    payload.insert(
        "adaptivity_rule".into(),
        json!("every turn was a pre-authored node of a digest-pinned acyclic strategy graph, selected by a closed observation class; nothing was generated"),
    );
    payload.insert(
        "bounded_claim_note".into(),
        json!("a PASS covers only the path the target selected; unreached nodes and behaviour outside the graph are not claimed"),
    );
    payload.insert(
        "separation_note".into(),
        json!("single-turn verdicts stay with Cycles 013-020; this record decides only the cross-turn property"),
    );
    let mut extensions = BTreeMap::new();
    extensions.insert(
        EXTENSION_NAMESPACE.to_owned(),
        serde_json::Value::Object(payload),
    );

    let mut hashes: Vec<HashRef> = result.graph_digests.iter().map(|d| bare_hash(d)).collect();
    hashes.extend(
        result
            .conversations
            .iter()
            .map(|c| bare_hash(&c.final_chain_digest)),
    );

    let evidence = SecurityEvidence {
        schema: SchemaRef {
            id: EVIDENCE_SCHEMA_ID.to_owned(),
            version: SchemaVersion::V1,
        },
        id: evidence_id(result, outcome)?,
        vector: VectorRef {
            id: result.scenario_id.to_string(),
            version: "1".to_owned(),
            name: None,
        },
        target: TargetRef {
            type_: if result.mode == HarnessMode::Replay {
                "replayed-agent"
            } else {
                "synthetic-agent"
            }
            .to_owned(),
            id: SYNTHETIC_TARGET_ID.to_owned(),
            name: Some("DARE multi-turn conversational target".to_owned()),
            software: None,
            software_version: None,
            protocol: None,
            protocol_version: None,
        },
        preconditions: vec![
            Precondition {
                id: Some("strategy_graph_pinned".to_owned()),
                description:
                    "every conversation ran a strategy graph whose digest the scenario pinned"
                        .to_owned(),
                satisfied: !result.graph_digests.is_empty(),
            },
            Precondition {
                id: Some("invariant_has_a_subject".to_owned()),
                description: "this invariant had something to decide in the scenario".to_owned(),
                satisfied: outcome.applicable,
            },
        ],
        operation: None,
        authorization_context: None,
        expected: ExpectedOutcome {
            decision: Some(Decision::Deny),
            result: Some(INVARIANT_HOLDS.to_owned()),
            description: Some(format!("cross-turn invariant {invariant} holds")),
        },
        observed: ObservedOutcome {
            // Cycle 001 derives the verdict from this comparison: only PASS and
            // FAIL may carry an observed decision. INCONCLUSIVE and ERROR must
            // leave it empty, or the record would read as a disguised FAIL.
            decision: match outcome.verdict {
                Verdict::Fail => Some(Decision::Allow),
                Verdict::Pass => Some(Decision::Deny),
                Verdict::Inconclusive | Verdict::Error => None,
            },
            result: Some(
                match outcome.verdict {
                    Verdict::Pass => INVARIANT_HOLDS,
                    Verdict::Fail => "invariant-violated",
                    Verdict::Inconclusive => "evidence-insufficient",
                    Verdict::Error => "harness-error",
                }
                .to_owned(),
            ),
            description: Some(format!("{invariant}: {}", outcome.reason)),
            source: ObservationSource::Fixture,
        },
        verdict: outcome.verdict,
        severity: None,
        standards: vec![StandardMapping {
            organization: "OWASP".to_owned(),
            standard: format!("Agentic Top 10 (2026) {}", asi_for(&outcome.property_id)),
            version: Some("2026".to_owned()),
            control: "NORMATIVE".to_owned(),
            url: None,
        }],
        artifacts: Vec::new(),
        hashes,
        redaction: RedactionMetadata {
            applied: true,
            strategy: RedactionStrategy::Mask,
            fields: vec![
                "observed.turn_content".to_owned(),
                "observed.target_output".to_owned(),
            ],
        },
        timestamps: EvidenceTimestamps {
            started_at: Some(now),
            observed_at: now,
            recorded_at: now,
        },
        extensions: Some(extensions),
    };
    validate_secret_safety(&evidence)
        .map_err(|_| MultiTurnError::SecretLikeContent { field: "evidence" })?;
    Ok(evidence)
}

/// One record per invariant, in `MultiTurnInvariant::ALL` order.
pub fn build_evidence(
    result: &MultiTurnResult,
    now: OffsetDateTime,
) -> Result<Vec<SecurityEvidence>> {
    result
        .invariants
        .iter()
        .map(|o| build_one(result, o, now))
        .collect()
}

/// `(property_id, evidence_id)` pairs for the coverage report.
pub fn evidence_index(
    records: &[SecurityEvidence],
    result: &MultiTurnResult,
) -> Vec<(String, String)> {
    result
        .invariants
        .iter()
        .zip(records)
        .map(|(o, r)| (o.property_id.clone(), r.id.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::OutputLedger;
    use crate::graph::tests::{edge, graph, node};
    use crate::limits::EffectiveBounds;
    use crate::model::fixtures::{graph_set, scenario};
    use crate::model::{MultiTurnInvariant, ObservationClass::*};
    use crate::result::run_scenario;
    use crate::simulated::{ReferenceAgent, SimulatedAdapter};
    use std::collections::BTreeSet;
    use time::macros::datetime;

    fn result(agent: ReferenceAgent) -> MultiTurnResult {
        let mut g = graph(
            vec![node("a", false), node("b", true), node("done", true)],
            vec![edge("a", Refused, "b"), edge("a", Complied, "done")],
        );
        g.nodes[0].turn.content = "CONFIDENTIAL-TEMPLATE-TEXT".into();
        let graphs = graph_set(&[g]);
        let s = scenario(MultiTurnInvariant::I01RefusalPersistence, &graphs);
        let mut adapter = SimulatedAdapter::new(agent, &s);
        run_scenario(
            &s,
            &graphs,
            &mut adapter,
            &mut OutputLedger::new(EffectiveBounds::default()),
            "2026-09-27T00:00:00Z",
        )
        .expect("runs")
        .0
    }

    #[test]
    fn one_valid_record_per_invariant_with_unique_ids() {
        let records = build_evidence(
            &result(ReferenceAgent::SecureRefuser),
            datetime!(2026-09-27 00:00 UTC),
        )
        .expect("builds");
        assert_eq!(records.len(), 7);
        let ids: BTreeSet<&str> = records.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids.len(), 7);
        for r in &records {
            dare_security_evidence::validate(r).expect("valid Cycle 001 evidence");
        }
    }

    #[test]
    fn every_verdict_produces_valid_cycle_001_evidence() {
        // PASS, FAIL and INCONCLUSIVE all occur across these runs.
        for agent in [
            ReferenceAgent::SecureRefuser,
            ReferenceAgent::ErodingRefusal {
                refusals_before_comply: 0,
            },
            ReferenceAgent::HarnessFailsAt { turn: 0 },
        ] {
            for r in
                build_evidence(&result(agent), datetime!(2026-09-27 00:00 UTC)).expect("builds")
            {
                dare_security_evidence::validate(&r)
                    .unwrap_or_else(|e| panic!("{agent:?} {}: {e:?}", r.id));
            }
        }
    }

    #[test]
    fn the_verdict_and_decision_follow_the_invariant() {
        let r = result(ReferenceAgent::ErodingRefusal {
            refusals_before_comply: 0,
        });
        let records = build_evidence(&r, datetime!(2026-09-27 00:00 UTC)).expect("builds");
        let i01 = &records[0];
        assert_eq!(i01.verdict, r.invariants[0].verdict);
    }

    #[test]
    fn records_carry_no_turn_content_or_canary() {
        let records = build_evidence(
            &result(ReferenceAgent::SecureRefuser),
            datetime!(2026-09-27 00:00 UTC),
        )
        .expect("builds");
        let json = serde_json::to_string(&records).expect("json");
        assert!(!json.contains("CONFIDENTIAL-TEMPLATE-TEXT"));
        assert!(!json.contains("CANARY-ABCDEF123456"));
    }

    #[test]
    fn each_record_maps_to_the_asi_of_its_family() {
        let records = build_evidence(
            &result(ReferenceAgent::SecureRefuser),
            datetime!(2026-09-27 00:00 UTC),
        )
        .expect("builds");
        let standards: Vec<&str> = records
            .iter()
            .map(|r| r.standards[0].standard.as_str())
            .collect();
        assert!(
            standards[2].ends_with("ASI03")
                && standards[4].ends_with("ASI09")
                && standards[6].ends_with("ASI06")
        );
        assert!(standards[0].ends_with("ASI01"));
    }
}
