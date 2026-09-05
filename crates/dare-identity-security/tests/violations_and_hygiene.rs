//! Independent multi-violation capture, and credential/redaction hygiene.
//!
//! Two properties this suite exists to hold:
//!
//! - **one classification never masks another.** A single trial can substitute
//!   the principal, cross a tenant and expand authority through a credential at
//!   the same time. All of those are true, and reporting only the first would
//!   under-report the finding — so violations are collected as a list, both
//!   within one invariant and across invariants.
//! - **nothing sensitive is retained.** Evidence text is masked before it is
//!   stored, by shape rather than by vocabulary, so a real credential never
//!   survives into an artifact while an honest sentence about credentials
//!   stays writable.

use std::collections::BTreeSet;
use std::path::PathBuf;

use dare_identity_security::harness::{normalize_checked, HarnessAdapter, TrialRequest};
use dare_identity_security::invariant::evaluate;
use dare_identity_security::model::{
    IdentityInvariantType, IdentitySecurityScenario, ReferenceBehavior,
};
use dare_identity_security::observation::{mask_sensitive, EvidenceText, IdentityObservationEvent};
use dare_identity_security::schema::validate_scenario_document;
use dare_identity_security::simulated::{stage, SimulatedAdapter};
use dare_identity_security::Verdict;

fn scenario(lab: &str) -> IdentitySecurityScenario {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/scenarios")
        .join(format!("{lab}.json"));
    let raw = std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    let value: serde_json::Value = serde_json::from_slice(&raw).expect("json");
    validate_scenario_document(&value).expect("valid scenario");
    let scenario: IdentitySecurityScenario = serde_json::from_value(value).expect("decodes");
    scenario.validate().expect("structurally valid");
    scenario
}

fn events(scenario: &IdentitySecurityScenario) -> Vec<IdentityObservationEvent> {
    let raw = SimulatedAdapter::new()
        .observe(&TrialRequest {
            trial_index: 0,
            scenario,
        })
        .expect("stages");
    normalize_checked(&raw, scenario).expect("normalizes")
}

// --- independent violation capture ---

#[test]
fn independent_violations_are_reported_independently() {
    let scenario = scenario("identity-lab-020");
    let observed = events(&scenario);

    let failing: BTreeSet<&'static str> = IdentityInvariantType::all()
        .into_iter()
        .filter(|invariant| evaluate(*invariant, &scenario, &observed).verdict == Verdict::Fail)
        .map(IdentityInvariantType::as_str)
        .collect();

    // Four distinct classifications, none of which suppresses another.
    for expected in [
        "INITIATING_PRINCIPAL_PRESERVED",
        "AGENT_AUTHORITY_NOT_SUBSTITUTED_FOR_USER",
        "TENANT_BOUNDARY_PRESERVED",
        "CREDENTIAL_CONTEXT_NOT_EXPAND_AUTHORITY",
    ] {
        assert!(
            failing.contains(expected),
            "{expected} missing from {failing:?}"
        );
    }
    assert!(
        failing.len() >= 4,
        "expected at least four independent findings, got {failing:?}"
    );
}

#[test]
fn a_violation_carries_its_own_reason_and_deciding_evidence() {
    let scenario = scenario("identity-lab-020");
    let observed = events(&scenario);

    for invariant in IdentityInvariantType::all() {
        let outcome = evaluate(invariant, &scenario, &observed);
        if outcome.verdict != Verdict::Fail {
            continue;
        }
        for violation in &outcome.violations {
            assert_eq!(violation.invariant, invariant);
            assert!(!violation.reason.is_empty());
            // Every reason is a statement about what was observed, never a
            // recommendation or a claim about the target's security posture.
            for banned in ["secure", "immune", "protected", "safe"] {
                assert!(
                    !violation.reason.to_lowercase().contains(banned),
                    "{}: `{}`",
                    invariant.as_str(),
                    violation.reason
                );
            }
        }
    }
}

#[test]
fn several_violations_of_one_invariant_are_all_listed() {
    // Two resources, both owned by the wrong principal: two violations of one
    // invariant, not one violation reported twice or one swallowing the other.
    let scenario = scenario("identity-lab-010");
    let mut raw = stage(&scenario, ReferenceBehavior::ResourceOwnerMismatched).expect("stages");
    let mut second = raw.resources[0].clone();
    second.resource_id = "document-456".to_owned();
    raw.resources.push(second);

    let observed = normalize_checked(&raw, &scenario).expect("normalizes");
    let outcome = evaluate(
        IdentityInvariantType::ResourceOwnerBoundaryPreserved,
        &scenario,
        &observed,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert_eq!(outcome.violations.len(), 2, "{:?}", outcome.violations);
    assert!(outcome
        .reason
        .contains("2 independently observed violations"));
}

#[test]
fn a_harness_error_never_becomes_a_violation() {
    // Failing to look is not the same as finding something.
    let scenario = scenario("identity-lab-002");
    let raw = stage(&scenario, ReferenceBehavior::HarnessFailure).expect("stages");
    let observed = normalize_checked(&raw, &scenario).expect("normalizes");

    for invariant in IdentityInvariantType::all() {
        let outcome = evaluate(invariant, &scenario, &observed);
        assert_eq!(outcome.verdict, Verdict::Error, "{}", invariant.as_str());
        assert!(outcome.violations.is_empty(), "{}", invariant.as_str());
        assert!(!outcome.coverage_satisfied, "{}", invariant.as_str());
    }
}

#[test]
fn an_observed_violation_is_never_downgraded_to_inconclusive() {
    // Ordering matters: violations are collected before coverage is assessed,
    // so a run that saw something never reports that it saw nothing.
    let scenario = scenario("identity-lab-008");
    let observed = events(&scenario);
    let outcome = evaluate(
        IdentityInvariantType::TenantBoundaryPreserved,
        &scenario,
        &observed,
    );
    assert_eq!(outcome.verdict, Verdict::Fail);
    assert!(outcome.coverage_satisfied);
}

// --- credential and redaction hygiene ---

#[test]
fn credential_shaped_values_never_survive_into_evidence_text() {
    let cases = [
        "sk-live-0123456789abcdef0123456789abcdef",
        "Bearer abcdefghijklmnopqrstuvwxyz012345",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.aaaaaaaaaaaaaaaaaaaa",
        "ghp_0123456789abcdef0123456789abcdef0123",
        "xoxb-0123456789-0123456789-abcdefghijkl",
        "-----BEGIN PRIVATE KEY----- MIIEvQIBADANBg",
        "DARE-SYNTHETIC-CANARY-IDENT01",
    ];

    for raw in cases {
        let evidence = EvidenceText::from_raw(raw);
        assert!(evidence.redacted, "{raw}");
        assert!(evidence.is_secret_safe(), "{raw}");
        for fragment in [
            "sk-live-0123",
            "abcdefghijklmnopqrstuvwxyz012345",
            "eyJhbGciOiJIUzI1NiJ9",
            "ghp_0123",
            "xoxb-0123",
            "MIIEvQIBADANBg",
            "IDENT01",
        ] {
            assert!(
                !evidence.text.contains(fragment),
                "`{fragment}` survived from `{raw}` into `{}`",
                evidence.text
            );
        }
    }
}

#[test]
fn a_secret_at_the_end_of_a_long_value_is_still_masked() {
    // A prefix-only scan would miss this, which is exactly how a secret ends up
    // in an artifact.
    let padding = "ordinary description text. ".repeat(200);
    let raw = format!("{padding}sk-live-0123456789abcdef0123456789abcdef");
    let evidence = EvidenceText::from_raw(&raw);
    assert!(evidence.redacted);
    assert!(!evidence.text.contains("sk-live-0123"));
}

#[test]
fn writing_honestly_about_credentials_stays_possible() {
    // Redaction is anchored on shape, not vocabulary. If the word were the
    // trigger, the sentence describing the boundary would be unwritable — and
    // a check that fires on ordinary prose is a check people turn off.
    for honest in [
        "this lab issues no bearer token and stores no credential",
        "the runtime holds a privileged service credential that is never exercised",
        "credential availability is not delegated authority",
        "no API key, password or private key is required",
    ] {
        assert_eq!(mask_sensitive(honest), honest, "`{honest}` was mangled");
        let evidence = EvidenceText::from_raw(honest);
        assert!(!evidence.redacted, "`{honest}`");
        assert_eq!(evidence.text, honest);
    }
}

#[test]
fn evidence_text_is_bounded_and_correlatable_without_the_original() {
    let raw = "x".repeat(100_000);
    let evidence = EvidenceText::from_raw(&raw);
    assert!(evidence.truncated);
    assert!(evidence.redacted);
    assert!(evidence.text.len() < raw.len());
    assert_eq!(evidence.original_bytes, raw.len());
    // The digest lets two occurrences be correlated without either being kept.
    assert!(evidence.digest.starts_with("sha256:"));
    assert_eq!(evidence.digest, EvidenceText::from_raw(&raw).digest);
    assert_ne!(evidence.digest, EvidenceText::from_raw("other").digest);
}

#[test]
fn no_normalized_event_from_any_lab_carries_unmasked_sensitive_text() {
    for index in 1..=24u32 {
        let lab = format!("identity-lab-{index:03}");
        let Ok(loaded) = std::panic::catch_unwind(|| scenario(&lab)) else {
            // Labs 018, 021 and 024 are refusal fixtures and never reach here.
            continue;
        };
        let Ok(raw) = stage(
            &loaded,
            loaded
                .lab
                .as_ref()
                .map(|spec| spec.reference_behavior)
                .unwrap_or(ReferenceBehavior::Compliant),
        ) else {
            continue;
        };
        let observed = normalize_checked(&raw, &loaded).expect("normalizes");
        let serialized = serde_json::to_string(&observed).expect("serializes");
        assert_eq!(
            mask_sensitive(&serialized),
            serialized,
            "{lab} retained sensitive-shaped content"
        );
    }
}
