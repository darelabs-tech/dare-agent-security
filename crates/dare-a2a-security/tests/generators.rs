//! Generator reproducibility and fixture safety.
//!
//! Cycle 020 introduces one generator — [`generate_agent_card`], which the
//! local-synthetic adapter uses to produce a document and read it back through
//! the real importer. A generator that drifted between runs would make every
//! regression argument in this cycle unfalsifiable, and the drift would not
//! look like a failure: the counts would still be right.
//!
//! The safety half applies to everything. No real credential, private key,
//! customer identifier or live A2A endpoint may appear in any fixture the
//! corpus stages or any artifact a run writes. That is asserted over the actual
//! bytes rather than over the source, because what matters is what reaches
//! disk.
//!
//! # The one distinction this file has to hold
//!
//! An Agent Card *is* a document full of locations. `https://peer.example/a2a`
//! must stay readable, or the engine cannot read a real card. What must not
//! appear is a host somebody could mistake for one this engine contacts, or a
//! value shaped like a real credential. The two are separated by the example
//! domains reserved for exactly this purpose, and
//! `an_example_interface_stays_and_a_real_host_does_not` pins the line.

use std::collections::BTreeSet;

use dare_a2a_security::budget::AdmissionLedger;
use dare_a2a_security::canonical::digest;
use dare_a2a_security::corpus::{corpus, scenario_for, A2aLabClass, CorpusAdapter};
use dare_a2a_security::evidence_bridge::build_evidence;
use dare_a2a_security::local_synthetic::generate_agent_card;
use dare_a2a_security::observation::project;
use dare_a2a_security::result::{render_summary, run_scenario};
use dare_a2a_security::schema::contains_bearer_credential;
use dare_a2a_security::source::ReferenceBehavior;
use time::macros::datetime;

/// Markers of the things that must never appear in a fixture or artifact.
///
/// Credential prefixes real providers issue, private-key armour, and the issuer
/// and API hosts a reader might mistake for something this engine reaches.
///
/// Example hosts are deliberately absent: `peer.example` has to stay readable,
/// or the fixtures could not describe an Agent Card at all. The line is between
/// a host reserved for documentation and one that resolves.
const FORBIDDEN: [&str; 18] = [
    "sk-live-",
    "sk_live_",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "-----BEGIN",
    "PRIVATE KEY",
    "client_secret=",
    "https://accounts.google.com",
    "https://login.microsoftonline.com",
    "https://api.openai.com",
    "https://api.anthropic.com",
    "https://oauth2.googleapis.com",
    "https://token.actions.githubusercontent.com",
    "@example-customer.com",
    "Authorization: Basic ",
];

fn assert_clean(label: &str, text: &str) {
    for marker in FORBIDDEN {
        assert!(
            !text.contains(marker),
            "{label} carries `{marker}`, which is a real credential, key or live endpoint"
        );
    }
    assert!(
        !contains_bearer_credential(&text.to_ascii_lowercase()),
        "{label} carries something shaped like a bearer credential"
    );
}

#[test]
fn every_generated_card_is_byte_identical_between_runs() {
    for behavior in ReferenceBehavior::all() {
        if behavior == ReferenceBehavior::HarnessFailure {
            continue;
        }
        let first = generate_agent_card(behavior);
        let second = generate_agent_card(behavior);
        assert_eq!(
            first, second,
            "{behavior:?} generates a different card each time"
        );
    }
}

#[test]
fn generated_cards_differ_between_behaviours_that_stage_different_things() {
    // The control for the test above. If the generator returned one constant,
    // byte-identity would hold trivially and prove nothing.
    let compliant = generate_agent_card(ReferenceBehavior::Compliant);
    let substituted = generate_agent_card(ReferenceBehavior::CardSubstituted);
    let unsigned = generate_agent_card(ReferenceBehavior::CardSignatureUnrecorded);
    let distinct: BTreeSet<&[u8]> = BTreeSet::from([
        compliant.as_slice(),
        substituted.as_slice(),
        unsigned.as_slice(),
    ]);
    assert!(
        distinct.len() > 1,
        "the generator returns the same card for behaviours that stage different things"
    );
}

#[test]
fn no_generated_card_carries_a_credential_key_or_live_endpoint() {
    for behavior in ReferenceBehavior::all() {
        if behavior == ReferenceBehavior::HarnessFailure {
            continue;
        }
        let raw = generate_agent_card(behavior);
        assert_clean(
            &format!("the card generated for {behavior:?}"),
            &String::from_utf8_lossy(&raw),
        );
    }
}

#[test]
fn no_corpus_bundle_carries_a_credential_key_or_live_endpoint() {
    for entry in corpus() {
        if entry.class == A2aLabClass::Refusal {
            continue;
        }
        let mut ledger = AdmissionLedger::new();
        let evidence = (entry.build)(&mut ledger).expect("stages");
        let rendered = serde_json::to_string(&evidence).expect("serializes");
        assert_clean(entry.id, &rendered);
    }
}

#[test]
fn no_artifact_a_run_writes_carries_a_credential_key_or_live_endpoint() {
    // Asserted over the bytes a run produces rather than over the fixtures it
    // reads. An artifact is what leaves the repository.
    for entry in corpus() {
        let scenario = scenario_for(&entry);
        let mut ledger = AdmissionLedger::new();
        let result = run_scenario(&scenario, &CorpusAdapter, &mut ledger).expect("runs");

        assert_clean(
            entry.id,
            &serde_json::to_string(&result).expect("serializes"),
        );
        assert_clean(entry.id, &render_summary(&result));

        let evidence =
            build_evidence(&scenario, &result, datetime!(2026-09-09 12:00 UTC)).expect("builds");
        assert_clean(
            entry.id,
            &serde_json::to_string(&evidence).expect("serializes"),
        );
    }
}

#[test]
fn an_example_interface_stays_and_a_real_host_does_not() {
    // The line this whole file turns on. An Agent Card is a document full of
    // locations, and an engine that could not carry one could not read a real
    // card. What must not appear is a host somebody could mistake for one this
    // engine reaches.
    let raw =
        String::from_utf8(generate_agent_card(ReferenceBehavior::Compliant)).expect("valid utf-8");
    assert!(
        raw.contains("peer.example"),
        "the generated card carries no interface at all"
    );
    assert_clean("the generated card", &raw);
}

#[test]
fn running_the_whole_corpus_twice_produces_identical_results() {
    // A corpus that produced different verdicts between runs would make every
    // future comparison meaningless, and the count would still look right.
    let run_all = || -> Vec<String> {
        corpus()
            .iter()
            .map(|entry| {
                let scenario = scenario_for(entry);
                let mut ledger = AdmissionLedger::new();
                let result = run_scenario(&scenario, &CorpusAdapter, &mut ledger).expect("runs");
                digest(&result).expect("digests")
            })
            .collect()
    };
    assert_eq!(run_all(), run_all());
}

#[test]
fn observation_digests_do_not_depend_on_the_order_evidence_arrived_in() {
    // The canonical-form claim, exercised rather than asserted. Every ordered
    // collection in the evidence model is a BTree for this reason, and a Vec
    // introduced later would fail here.
    for entry in corpus() {
        if entry.class == A2aLabClass::Refusal {
            continue;
        }
        let mut first_ledger = AdmissionLedger::new();
        let first = (entry.build)(&mut first_ledger).expect("stages");
        let mut second_ledger = AdmissionLedger::new();
        let second = (entry.build)(&mut second_ledger).expect("stages");
        assert_eq!(
            digest(&project(&first)).expect("digests"),
            digest(&project(&second)).expect("digests"),
            "{}",
            entry.id
        );
    }
}

#[test]
fn evidence_record_ids_are_reproducible_and_distinct() {
    let entries = corpus();
    let scenario = scenario_for(&entries[3]);
    let mut ledger = AdmissionLedger::new();
    let result = run_scenario(&scenario, &CorpusAdapter, &mut ledger).expect("runs");

    let first =
        build_evidence(&scenario, &result, datetime!(2026-09-09 12:00 UTC)).expect("builds");
    let second =
        build_evidence(&scenario, &result, datetime!(2026-09-09 12:00 UTC)).expect("builds");

    let left: Vec<&str> = first.iter().map(|record| record.id.as_str()).collect();
    let right: Vec<&str> = second.iter().map(|record| record.id.as_str()).collect();
    assert_eq!(left, right);

    let unique: BTreeSet<&str> = left.iter().copied().collect();
    assert_eq!(unique.len(), left.len(), "two records share an id");
}

#[test]
fn a_run_records_zero_state_changes_and_zero_egress_for_every_entry() {
    // The two numbers the whole cycle is defined by, checked on every vector
    // rather than once on a convenient one.
    for entry in corpus() {
        let scenario = scenario_for(&entry);
        let mut ledger = AdmissionLedger::new();
        let result = run_scenario(&scenario, &CorpusAdapter, &mut ledger).expect("runs");
        assert_eq!(result.budget.state_changes, 0, "{}", entry.id);
        assert_eq!(result.budget.external_egress_bytes, 0, "{}", entry.id);
    }
}
