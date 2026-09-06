//! Independent multi-violation capture and redaction before persistence.
//!
//! Two properties that are easy to lose and hard to notice losing.
//!
//! **All of them, not the first.** One returned document can breach the tenant
//! boundary, the chunk binding and the protected-document policy at once. An
//! engine that stops at the first finding reports a smaller problem than the
//! one it saw: the operator fixes the tenant leak, re-runs, and learns about
//! the rebound chunk — then fixes that and learns about the disclosure. Each
//! round trip looks like progress and none of them was the whole picture.
//!
//! **Redaction happens before anything is kept.** Evidence text, refusal
//! messages and observation records are all persistence surfaces. A canary or a
//! credential that reaches one of them has left the process, and masking it
//! afterwards is too late.

use std::path::PathBuf;

use dare_rag_security::harness::{normalize_checked, HarnessAdapter, TrialRequest};
use dare_rag_security::invariant::evaluate;
use dare_rag_security::model::{RagInvariantType, RagSecurityScenario};
use dare_rag_security::observation::{
    mask_sensitive, EvidenceText, RagObservationEvent, REDACTION_MARKER,
};
use dare_rag_security::schema::validate_scenario_document;
use dare_rag_security::simulated::SimulatedAdapter;
use dare_rag_security::Verdict;

fn load(lab: &str) -> RagSecurityScenario {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/scenarios")
        .join(format!("{lab}.json"));
    let bytes = std::fs::read(&path).expect("fixture readable");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    validate_scenario_document(&value).expect("admissible");
    let scenario: RagSecurityScenario = serde_json::from_value(value).expect("decodes");
    scenario.validate().expect("structurally valid");
    scenario
}

fn events(scenario: &RagSecurityScenario) -> Vec<RagObservationEvent> {
    let raw = SimulatedAdapter::new()
        .observe(&TrialRequest {
            trial_index: 0,
            scenario,
        })
        .expect("stages");
    normalize_checked(&raw, scenario).expect("normalizes")
}

/// The three invariants RAG-LAB-022 breaches at once.
const SIMULTANEOUS: [RagInvariantType; 3] = [
    RagInvariantType::RetrievalTenantBoundaryPreserved,
    RagInvariantType::ChunkDocumentBindingPreserved,
    RagInvariantType::ProtectedDocumentNotRetrieved,
];

#[test]
fn three_simultaneous_violations_are_all_reported_from_one_trial() {
    let scenario = load("rag-lab-022");
    let observed = events(&scenario);

    for invariant in SIMULTANEOUS {
        let outcome = evaluate(invariant, &scenario, &observed);
        assert_eq!(
            outcome.verdict,
            Verdict::Fail,
            "{invariant:?} did not fail: {}",
            outcome.reason
        );
        assert!(
            !outcome.violations.is_empty(),
            "{invariant:?} failed with no recorded violation, so nothing says why"
        );
        assert!(
            outcome
                .violations
                .iter()
                .all(|violation| violation.invariant == invariant),
            "{invariant:?} recorded a violation belonging to another invariant"
        );
    }
}

#[test]
fn evaluating_one_invariant_never_consumes_or_hides_another() {
    // Order independence. If evaluating the tenant invariant first changed what
    // the protected-document invariant could see, "first violation wins" would
    // be back in a subtler form.
    let scenario = load("rag-lab-022");
    let observed = events(&scenario);

    let forward: Vec<Verdict> = SIMULTANEOUS
        .iter()
        .map(|invariant| evaluate(*invariant, &scenario, &observed).verdict)
        .collect();

    let mut reversed_order = SIMULTANEOUS;
    reversed_order.reverse();
    let mut backward: Vec<Verdict> = reversed_order
        .iter()
        .map(|invariant| evaluate(*invariant, &scenario, &observed).verdict)
        .collect();
    backward.reverse();

    assert_eq!(forward, backward);
    assert!(forward.iter().all(|verdict| *verdict == Verdict::Fail));
}

#[test]
fn every_violation_names_the_events_that_decided_it() {
    // A finding with no deciding event is an assertion, not evidence. An
    // operator has to be able to go from the verdict back to the observation.
    let scenario = load("rag-lab-022");
    let observed = events(&scenario);

    for invariant in SIMULTANEOUS {
        for violation in evaluate(invariant, &scenario, &observed).violations {
            assert!(
                !violation.deciding_event_digests.is_empty(),
                "{invariant:?} recorded a violation with no deciding event"
            );
            assert!(
                !violation.reason.trim().is_empty(),
                "{invariant:?} recorded a violation with no reason"
            );
        }
    }
}

#[test]
fn a_failing_run_of_one_invariant_leaves_the_others_independently_judged() {
    // Lab 022 breaches a lot: ten of the twelve invariants fail on it, and all
    // ten are genuine — a retriever that returns a foreign document, a rebound
    // chunk and a protected document really has crossed the principal, tenant,
    // collection, ACL, filter, provenance, binding, candidate-set and top-k
    // boundaries at once, on top of the three the lab is named for.
    //
    // What must NOT happen is the twelfth invariant being dragged down with
    // them. Trust promotion is untouched by any of those breaches, and it has
    // to say so on its own. If failures propagated between evaluators, this
    // would fail too, and every report on a bad run would overstate itself.
    let scenario = load("rag-lab-022");
    let observed = events(&scenario);

    let untouched = evaluate(
        RagInvariantType::UntrustedRetrievedContentNotPromotedToAuthority,
        &scenario,
        &observed,
    );
    assert_eq!(
        untouched.verdict,
        Verdict::Pass,
        "an invariant nothing breached did not hold on its own: {}",
        untouched.reason
    );
    assert!(untouched.violations.is_empty());
}

#[test]
fn a_document_smuggled_past_the_filter_is_caught_from_the_corpus() {
    // The evasion the filter invariant has to survive: a retriever that records
    // honest admission decisions for the documents it really filtered, and none
    // at all for the one it slipped in. The coverage contract is satisfied by
    // the honest decisions, so a check that only read the decision channel
    // would report PASS on a document that was never filtered at all.
    //
    // Lab 022 stages exactly that. `doc-salary` reaches a result carrying no
    // `department` field, the policy makes `department` mandatory, and no
    // decision was ever recorded for it.
    let scenario = load("rag-lab-022");
    let observed = events(&scenario);

    // No decision was recorded for the smuggled document.
    let decided: Vec<&str> = observed
        .iter()
        .filter_map(|event| match event {
            RagObservationEvent::FilterDecision { document_id, .. } => Some(document_id.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        !decided.is_empty(),
        "the run recorded no filter decisions at all, so this test would be checking nothing"
    );
    assert!(
        !decided.contains(&"doc-salary"),
        "the fixture no longer smuggles the document, so the evasion is untested"
    );

    // It is caught anyway, from the corpus.
    let outcome = evaluate(
        RagInvariantType::MetadataFilterEnforced,
        &scenario,
        &observed,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert!(outcome
        .violations
        .iter()
        .any(
            |violation| violation.document_id.as_deref() == Some("doc-salary")
                && violation.reason.contains("department")
        ));
}

#[test]
fn a_violation_carries_the_object_it_is_about() {
    // "Something crossed a tenant boundary" is not actionable. The finding
    // names the document, so an operator knows what to look at.
    let scenario = load("rag-lab-002");
    let observed = events(&scenario);
    let outcome = evaluate(
        RagInvariantType::RetrievalTenantBoundaryPreserved,
        &scenario,
        &observed,
    );

    let violation = &outcome.violations[0];
    assert_eq!(violation.document_id.as_deref(), Some("doc-other-tenant"));
    assert!(violation.query_id.is_some());
}

#[test]
fn no_retained_text_from_any_lab_carries_a_canary_or_a_credential() {
    // Everything a run would keep: violation reasons, details and the outcome
    // reason itself. None of it may carry protected material.
    for index in 1..=22 {
        let lab = format!("rag-lab-{index:03}");
        let scenario = load(&lab);
        let observed = events(&scenario);

        let mut retained = Vec::new();
        for invariant in RagInvariantType::all() {
            let outcome = evaluate(invariant, &scenario, &observed);
            retained.push(outcome.reason.clone());
            for violation in outcome.violations {
                retained.push(violation.reason);
                if let Some(detail) = violation.detail {
                    retained.push(detail);
                }
            }
        }
        // The observation records are retained too.
        retained.push(serde_json::to_string(&observed).expect("serializes"));

        for text in retained {
            for canary in &scenario.objective.protected_canaries {
                assert!(
                    !text.contains(canary.as_str()),
                    "{lab} retained a protected canary in `{text}`"
                );
            }
            for marker in ["sk-live-", "-----BEGIN", "Bearer ey", "example.invalid"] {
                assert!(!text.contains(marker), "{lab} retained `{marker}`");
            }
        }
    }
}

#[test]
fn no_retained_text_ever_names_a_vector_store() {
    // The cycle's own boundary, checked against everything a run keeps.
    for index in 1..=22 {
        let lab = format!("rag-lab-{index:03}");
        let scenario = load(&lab);
        let serialized = serde_json::to_string(&events(&scenario)).expect("serializes");
        for store in [
            "pinecone",
            "weaviate",
            "qdrant",
            "redis://",
            "postgresql://",
            "opensearch",
            "elasticsearch",
        ] {
            assert!(
                !serialized.to_lowercase().contains(store),
                "{lab} named {store} in a retained observation"
            );
        }
    }
}

#[test]
fn masking_replaces_the_value_and_keeps_the_sentence_readable() {
    // A mask that erased the whole line would make evidence useless; one that
    // kept the value would make it dangerous.
    let masked = mask_sensitive("the result carried Authorization: Bearer abcdefghijklmnopqrst");
    assert!(masked.contains(REDACTION_MARKER));
    assert!(!masked.contains("abcdefghijklmnopqrst"));
    assert!(masked.contains("the result carried"));
}

#[test]
fn evidence_text_is_masked_at_construction_rather_than_on_the_way_out() {
    // The distinction that matters: if masking happened at render time, the
    // unmasked value would already be sitting in memory, in a serialized
    // record, and in whatever else read the struct first.
    let evidence =
        EvidenceText::from_raw("a chunk carried sk-live-000000000000000000000000 in its body");
    assert!(!evidence.text.contains("sk-live-"));
    assert!(evidence.text.contains(REDACTION_MARKER));
    assert!(evidence.redacted);
    assert!(evidence.is_secret_safe());

    let serialized = serde_json::to_string(&evidence).expect("serializes");
    assert!(!serialized.contains("sk-live-"));
}
