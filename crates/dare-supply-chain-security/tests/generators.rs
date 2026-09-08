//! Generator reproducibility and fixture safety.
//!
//! Cycle 019 introduces one generator — [`generate_cyclonedx`], which the
//! local-synthetic adapter uses to produce a document and read it back through
//! the real importer. AC-82 applies to it, and this file is where it is
//! discharged.
//!
//! AC-83 applies to everything: no real credential, private key, customer
//! identifier or live registry endpoint may appear in any fixture the corpus
//! stages or any artifact a run writes. That is asserted over the actual bytes
//! rather than over the source, because what matters is what reaches disk.

use std::collections::BTreeSet;

use dare_supply_chain_security::budget::AdmissionLedger;
use dare_supply_chain_security::canonical::digest;
use dare_supply_chain_security::corpus::{corpus, scenario_for, CorpusAdapter};
use dare_supply_chain_security::evidence_bridge::build_evidence;
use dare_supply_chain_security::local_synthetic::generate_cyclonedx;
use dare_supply_chain_security::result::run_scenario;
use dare_supply_chain_security::schema::contains_bearer_credential;
use dare_supply_chain_security::source::ReferenceBehavior;
use time::macros::datetime;

/// Markers of the things that must never appear in a fixture or artifact.
///
/// Credential prefixes real providers use, private-key armour, and the live
/// registry hosts a reader might mistake for something this engine contacts.
const FORBIDDEN: [&str; 16] = [
    "sk-live-",
    "sk_live_",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "AKIA",
    "-----BEGIN",
    "PRIVATE KEY",
    "https://registry.npmjs.org",
    "https://pypi.org",
    "https://index.crates.io",
    "https://huggingface.co",
    "https://ghcr.io",
    "https://rekor.sigstore.dev",
    "https://fulcio.sigstore.dev",
    "@example-customer.com",
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
fn every_generated_document_is_byte_identical_between_runs() {
    // AC-82. A report cites the digest of the document a run read. If the
    // generator produced different bytes each time, that digest would change
    // without anything about the run changing, and no regression could be
    // distinguished from noise.
    for behavior in ReferenceBehavior::all() {
        let first = generate_cyclonedx(behavior);
        let second = generate_cyclonedx(behavior);
        assert_eq!(
            first, second,
            "{behavior:?} generated two different documents"
        );
    }
}

#[test]
fn generated_documents_differ_between_behaviours_that_stage_different_things() {
    // The other half of reproducibility: identical output for every behaviour
    // would be reproducible and useless.
    let compliant = generate_cyclonedx(ReferenceBehavior::Compliant);
    for behavior in [
        ReferenceBehavior::AmbiguousDuplicateIdentity,
        ReferenceBehavior::DigestSubstituted,
        ReferenceBehavior::MutableReferenceUsedAsIdentity,
    ] {
        assert_ne!(
            compliant,
            generate_cyclonedx(behavior),
            "{behavior:?} generated the compliant document"
        );
    }
}

#[test]
fn no_generated_document_carries_a_credential_key_or_live_endpoint() {
    // AC-83, over the bytes rather than over the source.
    for behavior in ReferenceBehavior::all() {
        let raw = generate_cyclonedx(behavior);
        assert_clean(
            &format!("the {behavior:?} document"),
            &String::from_utf8(raw).expect("utf-8"),
        );
    }
}

#[test]
fn no_corpus_bundle_carries_a_credential_key_or_live_endpoint() {
    for entry in corpus() {
        let mut ledger = AdmissionLedger::new();
        let Ok(evidence) = (entry.build)(&mut ledger) else {
            continue;
        };
        assert_clean(
            entry.id,
            &serde_json::to_string(&evidence).expect("serializes"),
        );
    }
}

#[test]
fn no_artifact_a_run_writes_carries_a_credential_key_or_live_endpoint() {
    // The artifacts are what leave the process. A fixture that was clean and an
    // artifact that was not would still be a leak.
    for entry in corpus() {
        let scenario = scenario_for(&entry);
        let mut ledger = AdmissionLedger::new();
        let result = run_scenario(&scenario, &CorpusAdapter, &mut ledger).expect("runs");
        assert_clean(
            &format!("{} result", entry.id),
            &serde_json::to_string(&result).expect("serializes"),
        );

        let evidence =
            build_evidence(&scenario, &result, datetime!(2026-09-08 12:00 UTC)).expect("builds");
        assert_clean(
            &format!("{} evidence", entry.id),
            &serde_json::to_string(&evidence).expect("serializes"),
        );
    }
}

#[test]
fn a_purl_stays_in_the_fixtures_and_a_registry_host_does_not() {
    // The distinction the whole coordinate rule rests on. A purl names a
    // component; a registry URL names a place to fetch from. Real documents
    // carry the first, and a fixture carrying the second would be teaching the
    // corpus that a fetch target is normal content.
    let raw = String::from_utf8(generate_cyclonedx(ReferenceBehavior::Compliant)).expect("utf-8");
    assert!(raw.contains("pkg:npm/react@1.0.0"));
    assert!(!raw.contains("http"));
}

#[test]
fn running_the_whole_corpus_twice_produces_identical_results() {
    // AC-66 read as a regression rather than a count: a corpus that produced
    // different verdicts between runs would make every future comparison
    // meaningless, and the count would still look right.
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
fn evidence_record_ids_are_reproducible_and_distinct() {
    let scenario = scenario_for(&corpus()[3]);
    let mut ledger = AdmissionLedger::new();
    let result = run_scenario(&scenario, &CorpusAdapter, &mut ledger).expect("runs");

    let first =
        build_evidence(&scenario, &result, datetime!(2026-09-08 12:00 UTC)).expect("builds");
    let second =
        build_evidence(&scenario, &result, datetime!(2026-09-08 12:00 UTC)).expect("builds");

    let left: Vec<&str> = first.iter().map(|record| record.id.as_str()).collect();
    let right: Vec<&str> = second.iter().map(|record| record.id.as_str()).collect();
    assert_eq!(left, right);

    let unique: BTreeSet<&str> = left.iter().copied().collect();
    assert_eq!(unique.len(), left.len(), "two records share an id");
}
