//! Cycle 001 evidence bridge.
//!
//! Cycle 017 defines no second evidence contract and no second verdict
//! vocabulary. It emits `dare_security_evidence::SecurityEvidence` records and
//! puts retrieval specifics in the namespaced `extensions` container, which is
//! what that container exists for. A parallel contract would give the workspace
//! two shapes of evidence that agree until they quietly do not.
//!
//! Records are redacted before construction — the observation layer has already
//! masked canaries and credential shapes — and a final secret-safety check runs
//! before any record is returned. A record that would carry a secret is
//! refused, not trimmed: trimming hands back a clean-looking record from a
//! process that was willing to build a dirty one.

use std::collections::{BTreeMap, BTreeSet};

use dare_security_evidence::{
    validate_secret_safety, Decision, EvidenceTimestamps, ExpectedOutcome, HashRef,
    ObservationSource, ObservedOutcome, Precondition, RedactionMetadata, RedactionStrategy,
    SchemaRef, SchemaVersion, SecurityEvidence, StandardMapping, TargetRef, VectorRef, Verdict,
};
use serde_json::json;
use time::OffsetDateTime;

use crate::canonical::{digest, RagBinding};
use crate::error::{RagSecurityError, Result};
use crate::harness::HarnessMode;
use crate::model::{RagCorpusEntry, RagSecurityScenario};
use crate::result::{RagSecurityResult, RagTrialRecord};

pub const EVIDENCE_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/evidence/v1/evidence.schema.json";

/// Namespace for Cycle 017 evidence extensions.
pub const EXTENSION_NAMESPACE: &str = "dare.rag-security.v1";

/// The synthetic target Cycle 017 runs against. Never a production retriever.
pub const SYNTHETIC_TARGET_ID: &str = "synthetic-rag-security-lab";

/// Stable evidence identifier for one trial of one bound scenario.
///
/// Derived from every bound object plus the trial index, so the same run
/// produces the same identifiers and any substitution — of the corpus, a
/// document's content, a chunk, the policy or the context — produces different
/// ones. An id that stayed the same across a substituted corpus would let two
/// different runs be filed as the same evidence.
pub fn evidence_id(binding: &RagBinding, trial_index: u32) -> Result<String> {
    let identity = digest(&json!({
        "scenario_digest": binding.scenario_digest,
        "store_digest": binding.store_digest,
        "document_digests": binding.document_digests,
        "content_digests": binding.content_digests,
        "chunk_digests": binding.chunk_digests,
        "context_digest": binding.context_digest,
        "policy_digest": binding.policy_digest,
        "trial_index": trial_index,
    }))?;
    let hex = identity.trim_start_matches("sha256:");
    Ok(format!("urn:dare:rag-security:evidence:{hex}"))
}

/// Evidence identifiers for every executed trial.
pub fn evidence_ids(binding: &RagBinding, trials: &[RagTrialRecord]) -> Result<Vec<String>> {
    trials
        .iter()
        .map(|trial| evidence_id(binding, trial.index))
        .collect()
}

/// Stable result token for an invariant that held.
const INVARIANT_HOLDS: &str = "INVARIANT_HOLDS";
/// Stable result token for an invariant that was violated.
const INVARIANT_VIOLATED: &str = "INVARIANT_VIOLATED";

/// Observed outcome expressed in the Cycle 001 decision vocabulary.
///
/// The expected decision is always DENY: content outside the acting principal's
/// authority must not be returned. A held boundary is observed as DENY, a
/// crossed one as ALLOW. Undecidable and failed trials carry no decision at
/// all, which is what keeps INCONCLUSIVE and ERROR from being filed as either a
/// clean run or a finding.
fn observed_decision(verdict: Verdict) -> (Option<Decision>, Option<String>) {
    match verdict {
        Verdict::Pass => (Some(Decision::Deny), Some(INVARIANT_HOLDS.to_owned())),
        Verdict::Fail => (Some(Decision::Allow), Some(INVARIANT_VIOLATED.to_owned())),
        Verdict::Inconclusive | Verdict::Error => (None, None),
    }
}

fn observed_description(verdict: Verdict, invariant: &str) -> String {
    match verdict {
        Verdict::Pass => format!("invariant {invariant} held for this bounded trial"),
        Verdict::Fail => format!("invariant {invariant} was violated"),
        Verdict::Inconclusive => {
            format!("evidence was insufficient to decide invariant {invariant}")
        }
        Verdict::Error => format!("invariant {invariant} could not be evaluated"),
    }
}

/// Build one Cycle 001 evidence record for one trial.
pub fn build_trial_evidence(
    scenario: &RagSecurityScenario,
    entry: Option<&RagCorpusEntry>,
    binding: &RagBinding,
    result: &RagSecurityResult,
    trial: &RagTrialRecord,
    now: OffsetDateTime,
) -> Result<SecurityEvidence> {
    let invariant = result.invariant.as_str();

    // Built in groups and merged: one `json!` literal large enough to hold the
    // whole record exceeds the macro's recursion limit, and grouping keeps the
    // bound identities, the run facts and the standing notes legible.
    let bound = json!({
        "scenario_id": binding.scenario_id,
        "scenario_digest": binding.scenario_digest,
        "objective_id": binding.objective_id,
        "store_id": binding.store_id,
        "store_digest": binding.store_digest,
        "document_digests": result.document_digests,
        "chunk_digests": result.chunk_digests,
        "context_id": binding.context_id,
        "context_digest": binding.context_digest,
        // The isolation axes stay distinct in the record. Collapsing any two of
        // them is how a cross-boundary retrieval becomes invisible.
        "acting_principal_id": binding.acting_principal_id,
        "tenant_id": binding.tenant_id,
        "collection_ids": binding.collection_ids,
        "policy_id": binding.policy_id,
        "policy_digest": binding.policy_digest,
        "corpus_id": result.corpus_id,
        "corpus_digest": result.corpus_digest,
    });

    let run = json!({
        "property_id": result.property_id,
        "class": result.class,
        "source_kind": result.source_kind,
        "source_trust": result.source_trust,
        "mode": result.mode,
        "synthetic": result.synthetic,
        "invariant": invariant,
        "trial_index": trial.index,
        "trials_planned": result.trials_planned,
        "trials_executed": result.trials_executed,
        "stop_reason": result.stop_reason,
        "queries": trial.queries,
        "results": trial.results,
        "coverage_satisfied": trial.coverage_satisfied,
        "violations": trial.violations,
        "normalized_events": trial.events,
        "normalized_event_digests": trial.event_digests,
        "budget": result.budget,
        "controls": result.controls,
        "redaction_state": result.redaction_state,
    });

    let notes = json!({
        "retrieval_trust_relation": "similarity_match != permission",
        "content_rule": "retrieved_content != trusted_instruction",
        "score_rule":
            "high_score != safe_source. A score is evidence about ordering supplied by the \
             fixture or trace; it is never authorization, and no threshold on it decides a \
             verdict.",
        "authorization_rule":
            "A document may be highly relevant to a query and still lie outside the acting \
             principal's authority. Relevance is a property of the query; authorization is a \
             property of the policy.",
        "bounded_claim_note":
            "Verdicts are scoped to the tested vectors under the recorded conditions and never \
             assert that retrieval is secure, that leakage is impossible or that a vector \
             database is safe.",
        "execution_note":
            "Documents are described from local synthetic fixtures and never fetched. No \
             Pinecone, Weaviate, Qdrant, Redis, PostgreSQL, OpenSearch, Elasticsearch, SaaS \
             retrieval API, production retriever, customer corpus or remote MCP server is \
             involved; no embedding is computed; no state change or external egress occurs.",
        "separation_note":
            "Cycle 013 remains the final judge for prompt-injection and instruction-boundary \
             properties; Cycle 016 owns persisted memory, and retrieved content is not memory \
             unless a separate memory event stores it.",
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

    let preconditions: Vec<Precondition> = vec![
        Precondition {
            id: Some("local-only".to_owned()),
            description: "execution was local and offline".to_owned(),
            satisfied: true,
        },
        Precondition {
            id: Some("no-retrieval-dispatch".to_owned()),
            description: "documents were described from fixtures and never fetched from any index"
                .to_owned(),
            satisfied: true,
        },
        Precondition {
            id: Some("no-embedding-inference".to_owned()),
            description: "no embedding was computed, loaded or compared; scores are declared \
                          evidence about ordering"
                .to_owned(),
            satisfied: true,
        },
        Precondition {
            id: Some("corpus-bound".to_owned()),
            description: format!(
                "the document corpus was bound to the approved digest for {}",
                binding.store_id
            ),
            satisfied: true,
        },
        Precondition {
            id: Some("synthetic-documents".to_owned()),
            description: "every document, chunk, principal, tenant and collection was synthetic"
                .to_owned(),
            satisfied: true,
        },
        Precondition {
            id: Some("source-boundary".to_owned()),
            description: format!(
                "the retrieval corpus entered through the {} boundary",
                result.source_kind.as_str()
            ),
            satisfied: true,
        },
    ];

    // Attribution comes from the corpus vector when there is one, plus anything
    // the scenario declares. Duplicates collapse. A draft or proposal keeps its
    // own status; nothing here turns one into a conformance claim.
    let mut standards: Vec<StandardMapping> = Vec::new();
    let mut seen = BTreeSet::new();
    let entry_standards = entry.map(|entry| entry.standards.as_slice()).unwrap_or(&[]);
    for reference in entry_standards.iter().chain(scenario.standards.iter()) {
        if !seen.insert((reference.source.clone(), reference.reference.clone())) {
            continue;
        }
        standards.push(StandardMapping {
            organization: "OWASP".to_owned(),
            standard: reference.source.clone(),
            version: None,
            control: reference.reference.clone(),
            url: None,
        });
    }

    let mut hashes = vec![
        HashRef {
            algorithm: "sha256".to_owned(),
            value: strip(&binding.scenario_digest),
        },
        HashRef {
            algorithm: "sha256".to_owned(),
            value: strip(&binding.store_digest),
        },
        HashRef {
            algorithm: "sha256".to_owned(),
            value: strip(&binding.context_digest),
        },
        HashRef {
            algorithm: "sha256".to_owned(),
            value: strip(&binding.policy_digest),
        },
    ];
    if let Some(corpus_digest) = result.corpus_digest.as_ref() {
        hashes.push(HashRef {
            algorithm: "sha256".to_owned(),
            value: strip(corpus_digest),
        });
    }

    let (decision, outcome_result) = observed_decision(trial.verdict);
    let evidence = SecurityEvidence {
        schema: SchemaRef {
            id: EVIDENCE_SCHEMA_ID.to_owned(),
            version: SchemaVersion::V1,
        },
        id: evidence_id(binding, trial.index)?,
        vector: VectorRef {
            id: result
                .corpus_id
                .clone()
                .unwrap_or_else(|| binding.scenario_id.clone()),
            version: "1".to_owned(),
            name: scenario.title.clone(),
        },
        target: TargetRef {
            // Cycle 017 never targets a production retriever or a real corpus.
            type_: "synthetic-agent".to_owned(),
            id: SYNTHETIC_TARGET_ID.to_owned(),
            name: Some("DARE synthetic RAG-security lab".to_owned()),
            software: None,
            software_version: None,
            protocol: None,
            protocol_version: None,
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
            decision,
            result: outcome_result,
            description: Some(observed_description(trial.verdict, invariant)),
            // Observations come from local fixtures and traces, never a live
            // index or retrieval service.
            source: ObservationSource::Fixture,
        },
        verdict: trial.verdict,
        // Severity is never inferred from the verdict alone.
        severity: None,
        standards,
        artifacts: Vec::new(),
        hashes,
        redaction: RedactionMetadata {
            applied: true,
            strategy: RedactionStrategy::Mask,
            fields: vec![
                "observed.document_content".to_owned(),
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

    // Final gate: never return a record that carries a secret.
    validate_secret_safety(&evidence).map_err(|err| {
        RagSecurityError::refusal(format!("evidence failed secret-safety validation: {err}"))
    })?;

    Ok(evidence)
}

fn strip(digest: &str) -> String {
    digest.trim_start_matches("sha256:").to_owned()
}

/// Build Cycle 001 evidence for every executed trial.
pub fn build_evidence(
    scenario: &RagSecurityScenario,
    entry: Option<&RagCorpusEntry>,
    binding: &RagBinding,
    result: &RagSecurityResult,
    now: OffsetDateTime,
) -> Result<Vec<SecurityEvidence>> {
    result
        .trials
        .iter()
        .map(|trial| build_trial_evidence(scenario, entry, binding, result, trial, now))
        .collect()
}

/// Mode label recorded in evidence. Never a remote provider.
pub fn mode_label(mode: HarnessMode) -> &'static str {
    mode.as_str()
}

/// The Cycle 001 decision vocabulary, reused rather than redefined.
pub fn reused_decision_vocabulary() -> [Decision; 5] {
    [
        Decision::Allow,
        Decision::Deny,
        Decision::ReEvaluate,
        Decision::RequiresApproval,
        Decision::NotApplicable,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::bind;
    use crate::harness::tests::scenario;
    use crate::model::{RagInvariantType, ReferenceBehavior};
    use crate::result::run_scenario;
    use crate::simulated::SimulatedAdapter;
    use crate::trials::TrialPlan;

    fn fixed_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_767_225_600).expect("valid timestamp")
    }

    /// The invariant each staged behaviour actually bears on.
    ///
    /// Staging a tenant crossing while judging provenance would yield a verdict
    /// that says nothing about either, so the two are paired here.
    fn invariant_for(behavior: ReferenceBehavior) -> RagInvariantType {
        use RagInvariantType as I;
        match behavior {
            ReferenceBehavior::CrossTenantResult => I::RetrievalTenantBoundaryPreserved,
            ReferenceBehavior::ProtectedDocumentReturned => I::ProtectedDocumentNotRetrieved,
            ReferenceBehavior::ChunkReboundToAnotherDocument => I::ChunkDocumentBindingPreserved,
            ReferenceBehavior::UntrustedContentPromoted
            | ReferenceBehavior::RetrievedWithoutPromotion => {
                I::UntrustedRetrievedContentNotPromotedToAuthority
            }
            _ => I::RetrievalTenantBoundaryPreserved,
        }
    }

    fn run(behavior: ReferenceBehavior) -> (RagSecurityScenario, RagSecurityResult) {
        let mut scenario = scenario();
        scenario.lab.as_mut().expect("lab").reference_behavior = behavior;
        scenario.invariant.type_ = invariant_for(behavior);
        let plan = TrialPlan::from_scenario(&scenario).expect("plan");
        let result = run_scenario(&scenario, None, &SimulatedAdapter::new(), plan).expect("runs");
        (scenario, result)
    }

    fn evidence_for(behavior: ReferenceBehavior) -> Vec<SecurityEvidence> {
        let (scenario, result) = run(behavior);
        let binding = bind(&scenario).expect("binds");
        build_evidence(&scenario, None, &binding, &result, fixed_time()).expect("builds")
    }

    #[test]
    fn evidence_reuses_the_cycle_001_contract_and_vocabulary() {
        let records = evidence_for(ReferenceBehavior::Compliant);
        assert!(!records.is_empty());

        for record in &records {
            assert_eq!(record.schema.id, EVIDENCE_SCHEMA_ID);
            assert_eq!(record.schema.version, SchemaVersion::V1);
            assert_eq!(record.verdict, Verdict::Pass);
            assert_eq!(record.expected.decision, Some(Decision::Deny));
            assert_eq!(record.observed.decision, Some(Decision::Deny));
            assert_eq!(record.observed.source, ObservationSource::Fixture);
        }
    }

    #[test]
    fn retrieval_specifics_live_in_the_namespaced_extension_and_nowhere_else() {
        let records = evidence_for(ReferenceBehavior::Compliant);
        let extensions = records[0]
            .extensions
            .as_ref()
            .expect("extensions are present");

        assert_eq!(extensions.len(), 1, "a second namespace would be a fork");
        let payload = extensions
            .get(EXTENSION_NAMESPACE)
            .expect("the Cycle 017 namespace");

        for key in [
            "store_digest",
            "acting_principal_id",
            "tenant_id",
            "collection_ids",
            "policy_digest",
            "invariant",
            "retrieval_trust_relation",
        ] {
            assert!(payload.get(key).is_some(), "missing `{key}`");
        }
    }

    #[test]
    fn the_central_relations_are_stated_in_every_record() {
        // Every artifact carries the rules it was produced under, so a record
        // read on its own still says what a retrieval verdict does and does not
        // mean.
        for behavior in [
            ReferenceBehavior::Compliant,
            ReferenceBehavior::CrossTenantResult,
        ] {
            for record in evidence_for(behavior) {
                let payload =
                    record.extensions.as_ref().expect("extensions")[EXTENSION_NAMESPACE].clone();
                assert_eq!(
                    payload["retrieval_trust_relation"],
                    "similarity_match != permission"
                );
                assert_eq!(
                    payload["content_rule"],
                    "retrieved_content != trusted_instruction"
                );
                assert!(payload["score_rule"]
                    .as_str()
                    .expect("a string")
                    .contains("high_score != safe_source"));
            }
        }
    }

    #[test]
    fn a_violation_is_observed_as_allow_and_never_as_a_severity() {
        let records = evidence_for(ReferenceBehavior::CrossTenantResult);
        let failing: Vec<_> = records
            .iter()
            .filter(|record| record.verdict == Verdict::Fail)
            .collect();
        assert!(!failing.is_empty());

        for record in failing {
            assert_eq!(record.observed.decision, Some(Decision::Allow));
            assert_eq!(record.observed.result.as_deref(), Some(INVARIANT_VIOLATED));
            // Severity is a judgement about impact, which this engine has no
            // basis to make from a synthetic lab.
            assert!(record.severity.is_none());
        }
    }

    #[test]
    fn an_undecidable_trial_carries_no_decision_in_either_direction() {
        // The failure mode this prevents: an INCONCLUSIVE record filed with a
        // DENY decision reads downstream as a clean run.
        let mut scenario = scenario();
        scenario.lab.as_mut().expect("lab").reference_behavior =
            ReferenceBehavior::NoRelevantObservation;
        let plan = TrialPlan::from_scenario(&scenario).expect("plan");
        let result = run_scenario(&scenario, None, &SimulatedAdapter::new(), plan).expect("runs");
        let binding = bind(&scenario).expect("binds");
        let records =
            build_evidence(&scenario, None, &binding, &result, fixed_time()).expect("builds");

        for record in records {
            assert_eq!(record.verdict, Verdict::Inconclusive);
            assert!(record.observed.decision.is_none());
            assert!(record.observed.result.is_none());
        }
    }

    #[test]
    fn every_record_targets_the_synthetic_lab_and_says_so() {
        for record in evidence_for(ReferenceBehavior::Compliant) {
            assert_eq!(record.target.id, SYNTHETIC_TARGET_ID);
            assert_eq!(record.target.type_, "synthetic-agent");
            assert!(record.target.protocol.is_none());
            assert!(record.preconditions.iter().any(|precondition| {
                precondition.id.as_deref() == Some("local-only") && precondition.satisfied
            }));
            // The one precondition unique to this cycle.
            assert!(record.preconditions.iter().any(|precondition| {
                precondition.id.as_deref() == Some("no-embedding-inference")
                    && precondition.satisfied
            }));
        }
    }

    #[test]
    fn the_execution_note_names_every_store_cycle_017_never_touches() {
        let records = evidence_for(ReferenceBehavior::Compliant);
        let payload =
            records[0].extensions.as_ref().expect("extensions")[EXTENSION_NAMESPACE].clone();
        let note = payload["execution_note"].as_str().expect("a string");

        for absent in [
            "Pinecone",
            "Weaviate",
            "Qdrant",
            "Redis",
            "PostgreSQL",
            "OpenSearch",
            "Elasticsearch",
            "customer corpus",
        ] {
            assert!(note.contains(absent), "the note omits {absent}");
        }
        assert!(note.contains("no embedding is computed"));
    }

    #[test]
    fn the_separation_note_names_both_adjacent_cycles() {
        let records = evidence_for(ReferenceBehavior::Compliant);
        let payload =
            records[0].extensions.as_ref().expect("extensions")[EXTENSION_NAMESPACE].clone();
        let note = payload["separation_note"].as_str().expect("a string");
        assert!(note.contains("Cycle 013"));
        assert!(note.contains("Cycle 016"));
        assert!(note.contains("not memory"));
    }

    #[test]
    fn no_record_claims_conformance_or_universal_safety() {
        for behavior in ReferenceBehavior::all() {
            let mut scenario = scenario();
            scenario.lab.as_mut().expect("lab").reference_behavior = behavior;
            scenario.invariant.type_ = invariant_for(behavior);
            let plan = TrialPlan::from_scenario(&scenario).expect("plan");
            let Ok(result) = run_scenario(&scenario, None, &SimulatedAdapter::new(), plan) else {
                continue;
            };
            let binding = bind(&scenario).expect("binds");
            let records =
                build_evidence(&scenario, None, &binding, &result, fixed_time()).expect("builds");

            let serialized = serde_json::to_string(&records).expect("serializes");
            for banned in [
                "RAG Secure",
                "Vector Database Secure",
                "No Leakage Possible",
                "Fully Protected",
                "No Retrieval Attack Possible",
                "certified",
                "compliant with",
            ] {
                assert!(!serialized.contains(banned), "{behavior:?}: {banned}");
            }
        }
    }

    #[test]
    fn evidence_ids_are_stable_and_move_when_the_corpus_moves() {
        let (scenario, result) = run(ReferenceBehavior::Compliant);
        let binding = bind(&scenario).expect("binds");
        let first = evidence_id(&binding, 0).expect("id");
        assert_eq!(first, evidence_id(&binding, 0).expect("id"));
        assert!(first.starts_with("urn:dare:rag-security:evidence:"));

        // A substituted document's content moves the id, so two different runs
        // cannot be filed as the same evidence.
        let mut swapped = scenario.clone();
        swapped.store.documents[0].content_digest =
            crate::canonical::content_digest("substituted content");
        let moved = evidence_id(&bind(&swapped).expect("binds"), 0).expect("id");
        assert_ne!(first, moved);

        // And the trial index separates trials of the same run.
        assert_ne!(first, evidence_id(&binding, 1).expect("id"));
        assert_eq!(result.evidence_ids.len(), result.trials.len());
    }

    #[test]
    fn every_bound_digest_reaches_the_record_hashes() {
        let (scenario, result) = run(ReferenceBehavior::Compliant);
        let binding = bind(&scenario).expect("binds");
        let records =
            build_evidence(&scenario, None, &binding, &result, fixed_time()).expect("builds");

        let hashes: Vec<&str> = records[0]
            .hashes
            .iter()
            .map(|hash| hash.value.as_str())
            .collect();
        for digest in [
            &binding.scenario_digest,
            &binding.store_digest,
            &binding.context_digest,
            &binding.policy_digest,
        ] {
            assert!(
                hashes.contains(&strip(digest).as_str()),
                "a bound digest is missing from the record"
            );
        }
    }

    #[test]
    fn the_decision_vocabulary_is_borrowed_rather_than_redefined() {
        assert_eq!(reused_decision_vocabulary().len(), 5);
        assert_eq!(mode_label(HarnessMode::Simulated), "SIMULATED");
    }
}
