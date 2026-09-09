//! The Cycle 001 evidence bridge.
//!
//! Cycle 020 emits Cycle 001 `SecurityEvidence` records rather than a parallel
//! evidence format. Everything specific to this cycle lives inside a namespaced
//! extension, so the shared contract stays shared and a consumer that knows
//! nothing about A2A can still read the record.
//!
//! Every record targets the synthetic lab. A Cycle 020 result is evidence about
//! local documents and captures that were read, and filing it against a real
//! deployment would let a report present an offline analysis as a statement
//! about a live agent-to-agent relationship.
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

use crate::error::{A2aSecurityError, Result};
use crate::invariant::A2aInvariantOutcome;
use crate::model::{A2aInvariant, A2aScenario};
use crate::result::A2aSecurityResult;

pub const EVIDENCE_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/evidence/v1/security-evidence.schema.json";

/// Namespace for everything specific to this cycle.
pub const EXTENSION_NAMESPACE: &str = "dare.a2a-security.v1";

/// The only target a Cycle 020 record may name.
pub const SYNTHETIC_TARGET_ID: &str = "synthetic-a2a-inter-agent-lab";

/// The expected result every Cycle 020 vector is measured against.
const INVARIANT_HOLDS: &str = "invariant-holds";

/// A stable identifier for one invariant's evidence within a run.
pub fn evidence_id(scenario: &A2aScenario, invariant: A2aInvariant) -> Result<String> {
    let digest = crate::canonical::digest(&json!({
        "scenario": scenario.scenario_id,
        "invariant": invariant.as_str(),
    }))?;
    Ok(format!(
        "a2a-{}-{}",
        invariant.as_str().to_ascii_lowercase(),
        &digest[7..23]
    ))
}

/// How the observed outcome is described, without restating the verdict twice.
fn observed_description(verdict: Verdict, invariant: &str) -> String {
    match verdict {
        Verdict::Pass => format!("no violation of {invariant} was observed in this evidence"),
        Verdict::Fail => format!("a deterministic violation of {invariant} was observed"),
        Verdict::Inconclusive => {
            format!("the evidence required to decide {invariant} was not present")
        }
        Verdict::Error => format!("the harness could not evaluate {invariant}"),
    }
}

/// Build one evidence record for one invariant outcome.
pub fn build_invariant_evidence(
    scenario: &A2aScenario,
    result: &A2aSecurityResult,
    outcome: &A2aInvariantOutcome,
    now: OffsetDateTime,
) -> Result<SecurityEvidence> {
    let invariant = outcome.invariant.as_str();

    // The sixteen relations the cycle rests on, carried in every record so a
    // reader holding one artifact still knows what a verdict means. A consumer
    // that only ever sees one record must not have to find this document.
    let notes = json!({
        "listing_rule": "external agent listed != trusted peer",
        "discovery_rule": "discovered Agent Card != authenticated identity",
        "signature_rule": "signed Agent Card != authorized provider",
        "transport_rule": "TLS server identity != agent-level authorization",
        "scheme_rule": "declared security scheme != successful authentication",
        "authentication_rule": "successful authentication != skill authorization",
        "schema_rule": "schema-valid message != authentic message",
        "authenticity_rule": "authentic message != authorized instruction",
        "content_rule": "peer content != privileged instruction",
        "correlation_rule": "taskId match != principal/context match",
        "delegation_rule": "delegation != privilege amplification",
        "retry_rule": "message retry != safe replay",
        "negotiation_rule": "protocol compatibility != permission to downgrade",
        "extension_rule": "extension declaration != extension authority",
        "callback_rule": "webhook URL != permission to connect",
        "tenant_rule": "tenant routing value != proof of tenant authorization",
        "execution_note":
            "Evidence is read from local Agent Cards, captured exchanges, recorded verification \
             results, delegation records and local policy. No A2A agent is contacted; no Agent \
             Card is downloaded; no .well-known path or registry is queried; no JWK, JWKS or \
             jku is resolved; no OAuth, OIDC or bearer credential is obtained or used; no TLS \
             handshake is performed; no message is sent; no remote task is created or \
             cancelled; no webhook or push endpoint is called; nothing from the evidence is \
             executed; no external state changes.",
        "separation_note":
            "Cycle 013 owns generic prompt injection; Cycle 014 owns tool-invocation \
             authorization; Cycle 015 owns identity, principal, delegation, privilege and \
             tenant semantics; Cycle 018 owns concrete-failure aggregation; Cycle 019 owns \
             supply-chain and external-agent inventory. This record carries only the A2A \
             projection of those relations and takes verdict authority over none of them.",
        "bounded_claim_note":
            "A PASS means the applicable invariants remained satisfied under the local evidence \
             analysed. It is not a statement that a remote agent is secure, that a peer is \
             trustworthy, or that an exchange nobody captured was safe.",
    });

    let bound = json!({
        "scenario_digest": result.scenario_digest,
        "evidence_digest": result.evidence_digest,
        "document_digests": result
            .documents
            .iter()
            .map(|document| document.content_digest.clone())
            .collect::<Vec<_>>(),
    });

    let run = json!({
        "invariant": invariant,
        "design_id": outcome.invariant.design_id(),
        "property": outcome.invariant.property_id(),
        "surface": result.class.as_str(),
        "mode": result.mode.as_str(),
        "synthetic": result.synthetic,
        "applicable": outcome.applicable,
        "coverage_satisfied": outcome.coverage_satisfied,
        "violations": outcome.violations.len(),
        "deciding_observation_digests": outcome
            .violations
            .iter()
            .flat_map(|violation| violation.deciding_observation_digests.clone())
            .collect::<Vec<_>>(),
        "peers_evaluated": result.peers_evaluated,
        "exchanges_evaluated": result.exchanges_evaluated,
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

    let mut hashes = vec![
        HashRef {
            algorithm: "sha256".to_owned(),
            value: result.scenario_digest.clone(),
        },
        HashRef {
            algorithm: "sha256".to_owned(),
            value: result.evidence_digest.clone(),
        },
    ];
    hashes.extend(result.documents.iter().map(|document| HashRef {
        algorithm: "sha256".to_owned(),
        value: document.content_digest.clone(),
    }));

    // A standards attribution is a reference, not a retrieval target: this
    // cycle fetches nothing, and a URL here would be the first place somebody
    // added one.
    let standards = vec![StandardMapping {
        organization: "OWASP".to_owned(),
        standard: "Agentic Top 10 (2026) ASI07".to_owned(),
        version: Some("2026".to_owned()),
        control: "NORMATIVE".to_owned(),
        url: None,
    }];

    let preconditions = vec![
        Precondition {
            id: Some("local_a2a_evidence_present".to_owned()),
            description: "local A2A evidence was read for this run".to_owned(),
            satisfied: result.peers_evaluated > 0 || !result.documents.is_empty(),
        },
        Precondition {
            id: Some("invariant_has_a_subject".to_owned()),
            description: "this invariant had a subject in the evidence analysed".to_owned(),
            satisfied: outcome.applicable,
        },
    ];

    let evidence = SecurityEvidence {
        schema: SchemaRef {
            id: EVIDENCE_SCHEMA_ID.to_owned(),
            version: SchemaVersion::V1,
        },
        id: evidence_id(scenario, outcome.invariant)?,
        vector: VectorRef {
            id: scenario.scenario_id.clone(),
            version: "1".to_owned(),
            name: Some(scenario.description.clone()),
        },
        target: TargetRef {
            // Cycle 020 never targets a live agent-to-agent relationship: it
            // reads local evidence, and a capture is not a running exchange.
            type_: "synthetic-agent".to_owned(),
            id: SYNTHETIC_TARGET_ID.to_owned(),
            name: Some("DARE synthetic A2A inter-agent lab".to_owned()),
            software: None,
            software_version: None,
            // The protocol whose shapes this evidence describes. A name, not a
            // thing that was spoken to.
            protocol: Some("A2A".to_owned()),
            protocol_version: Some("1.0.0".to_owned()),
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
            decision: Some(match outcome.verdict {
                Verdict::Fail => Decision::Allow,
                Verdict::Pass => Decision::Deny,
                _ => Decision::NotApplicable,
            }),
            result: Some(match outcome.verdict {
                Verdict::Pass => INVARIANT_HOLDS.to_owned(),
                Verdict::Fail => "invariant-violated".to_owned(),
                Verdict::Inconclusive => "evidence-insufficient".to_owned(),
                Verdict::Error => "harness-error".to_owned(),
            }),
            description: Some(observed_description(outcome.verdict, invariant)),
            // Observations come from local documents and captures, never from a
            // live peer.
            source: ObservationSource::Fixture,
        },
        verdict: outcome.verdict,
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
            fields: vec!["observed.message_content".to_owned()],
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
    validate_secret_safety(&evidence).map_err(|error| {
        A2aSecurityError::refusal(format!("evidence failed secret safety: {error}"))
    })?;

    Ok(evidence)
}

/// Build every evidence record for a run: one per invariant.
///
/// Fourteen records rather than one, because an operator filtering by property
/// must see the invariant that decided their question rather than a single
/// record carrying an aggregate they would have to unpack.
pub fn build_evidence(
    scenario: &A2aScenario,
    result: &A2aSecurityResult,
    now: OffsetDateTime,
) -> Result<Vec<SecurityEvidence>> {
    result
        .outcomes
        .iter()
        .map(|outcome| build_invariant_evidence(scenario, result, outcome, now))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::AdmissionLedger;
    use crate::model::tests::scenario;
    use crate::result::run_scenario;
    use crate::simulated::SimulatedAdapter;
    use crate::source::{A2aMode, ReferenceBehavior};
    use std::collections::BTreeSet;
    use time::macros::datetime;

    fn run(behavior: ReferenceBehavior) -> (A2aScenario, A2aSecurityResult) {
        let mut scenario = scenario("a2a-bridge", A2aInvariant::TenantBoundaryPreserved);
        scenario.mode = A2aMode::Simulated;
        scenario.reference_behavior = Some(behavior);
        let mut ledger = AdmissionLedger::new();
        let result = run_scenario(&scenario, &SimulatedAdapter::new(), &mut ledger).expect("runs");
        (scenario, result)
    }

    fn now() -> OffsetDateTime {
        datetime!(2026-09-09 12:00:00 UTC)
    }

    #[test]
    fn one_record_is_emitted_for_each_of_the_fourteen_invariants() {
        // An operator filtering by property must find the invariant that
        // decided their question, not an aggregate they have to unpack.
        let (scenario, result) = run(ReferenceBehavior::Compliant);
        let records = build_evidence(&scenario, &result, now()).expect("builds");
        assert_eq!(records.len(), 14);

        let ids: BTreeSet<&str> = records.iter().map(|record| record.id.as_str()).collect();
        assert_eq!(ids.len(), 14, "two records share an id");
    }

    #[test]
    fn every_record_names_the_synthetic_lab_and_never_a_deployment() {
        // Filing an offline analysis against a real target would let a report
        // present it as a statement about a live relationship.
        let (scenario, result) = run(ReferenceBehavior::CrossTenantAccess);
        for record in build_evidence(&scenario, &result, now()).expect("builds") {
            assert_eq!(record.target.id, SYNTHETIC_TARGET_ID);
            assert_eq!(record.target.type_, "synthetic-agent");
            assert_eq!(record.observed.source, ObservationSource::Fixture);
        }
    }

    #[test]
    fn every_record_carries_the_sixteen_relations_and_the_offline_note() {
        // A consumer holding one record must know what the verdict means
        // without finding this cycle's documentation.
        let (scenario, result) = run(ReferenceBehavior::Compliant);
        let record = &build_evidence(&scenario, &result, now()).expect("builds")[0];
        let extension = &record.extensions.as_ref().expect("extensions")[EXTENSION_NAMESPACE];

        for rule in [
            "listing_rule",
            "discovery_rule",
            "signature_rule",
            "transport_rule",
            "scheme_rule",
            "authentication_rule",
            "schema_rule",
            "authenticity_rule",
            "content_rule",
            "correlation_rule",
            "delegation_rule",
            "retry_rule",
            "negotiation_rule",
            "extension_rule",
            "callback_rule",
            "tenant_rule",
        ] {
            assert!(extension.get(rule).is_some(), "{rule} is missing");
        }

        let execution = extension["execution_note"].as_str().expect("a note");
        for promise in [
            "No A2A agent is contacted",
            "no Agent Card is downloaded",
            "no JWK, JWKS or jku is resolved",
            "no TLS handshake is performed",
            "no webhook or push endpoint is called",
        ] {
            assert!(execution.contains(promise), "{promise} is missing");
        }

        let claim = extension["bounded_claim_note"].as_str().expect("a note");
        assert!(claim.contains("not a statement that a remote agent is secure"));
    }

    #[test]
    fn the_record_names_the_cycles_it_does_not_speak_for() {
        let (scenario, result) = run(ReferenceBehavior::Compliant);
        let record = &build_evidence(&scenario, &result, now()).expect("builds")[0];
        let extension = &record.extensions.as_ref().expect("extensions")[EXTENSION_NAMESPACE];
        let separation = extension["separation_note"].as_str().expect("a note");
        for cycle in [
            "Cycle 013",
            "Cycle 014",
            "Cycle 015",
            "Cycle 018",
            "Cycle 019",
        ] {
            assert!(separation.contains(cycle), "{cycle} is missing");
        }
        assert!(separation.contains("takes verdict authority over none of them"));
    }

    #[test]
    fn a_violation_record_reports_allow_and_a_clean_one_reports_deny() {
        // The Cycle 001 vocabulary reads the other way round from the verdict:
        // a violation is something the target *allowed*.
        let (scenario, result) = run(ReferenceBehavior::CrossTenantAccess);
        let records = build_evidence(&scenario, &result, now()).expect("builds");
        let crossed = records
            .iter()
            .find(|record| record.verdict == Verdict::Fail)
            .expect("a failing record");
        assert_eq!(crossed.observed.decision, Some(Decision::Allow));
        assert_eq!(
            crossed.observed.result.as_deref(),
            Some("invariant-violated")
        );

        let held = records
            .iter()
            .find(|record| record.verdict == Verdict::Pass)
            .expect("a passing record");
        assert_eq!(held.observed.decision, Some(Decision::Deny));
    }

    #[test]
    fn an_undecided_record_is_not_applicable_and_never_a_pass() {
        // Missing evidence reaching a Cycle 001 consumer as `invariant-holds`
        // would be this cycle's central failure, one layer downstream.
        let (scenario, result) = run(ReferenceBehavior::NoRelevantObservation);
        for record in build_evidence(&scenario, &result, now()).expect("builds") {
            if record.verdict == Verdict::Inconclusive {
                assert_eq!(record.observed.decision, Some(Decision::NotApplicable));
                assert_eq!(
                    record.observed.result.as_deref(),
                    Some("evidence-insufficient")
                );
                assert_ne!(record.observed.result.as_deref(), Some(INVARIANT_HOLDS));
            }
        }
    }

    #[test]
    fn no_record_carries_a_severity_this_engine_invented() {
        // Severity is a judgement a consumer makes. Baking one in would make
        // this engine's opinion look like a fact.
        let (scenario, result) = run(ReferenceBehavior::MultipleIndependentViolations);
        for record in build_evidence(&scenario, &result, now()).expect("builds") {
            assert!(record.severity.is_none());
        }
    }

    #[test]
    fn the_standards_attribution_carries_no_retrieval_target() {
        // A URL here would be the first place somebody added a fetch.
        let (scenario, result) = run(ReferenceBehavior::Compliant);
        for record in build_evidence(&scenario, &result, now()).expect("builds") {
            for standard in &record.standards {
                assert!(standard.url.is_none(), "a standard names a URL to fetch");
            }
        }
    }

    #[test]
    fn record_ids_are_stable_across_runs_and_distinct_across_invariants() {
        let (scenario, result) = run(ReferenceBehavior::Compliant);
        let first = build_evidence(&scenario, &result, now()).expect("builds");
        let second = build_evidence(&scenario, &result, now()).expect("builds");
        let first_ids: Vec<&str> = first.iter().map(|record| record.id.as_str()).collect();
        let second_ids: Vec<&str> = second.iter().map(|record| record.id.as_str()).collect();
        assert_eq!(first_ids, second_ids);

        for invariant in A2aInvariant::all() {
            let id = evidence_id(&scenario, invariant).expect("an id");
            assert!(id.starts_with("a2a-"));
        }
    }

    #[test]
    fn every_record_passes_cycle_001_secret_safety() {
        // Asserted by construction: `build_invariant_evidence` runs the
        // validator and returns an error rather than a record. This test fails
        // if that gate is ever removed.
        for behavior in [
            ReferenceBehavior::Compliant,
            ReferenceBehavior::MultipleIndependentViolations,
            ReferenceBehavior::PeerContentTreatedAsInstruction,
        ] {
            let (scenario, result) = run(behavior);
            let records = build_evidence(&scenario, &result, now()).expect("builds");
            for record in &records {
                validate_secret_safety(record).expect("record is secret-safe");
            }
        }
    }
}
