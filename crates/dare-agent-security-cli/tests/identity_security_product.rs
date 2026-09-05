//! Cycle 015 product-reporting integration.
//!
//! `dare-product` stays protocol-neutral: it takes plain outcome records rather
//! than the engine's types. That keeps the layers apart, but it also means
//! nothing inside either crate proves the two agree. This suite is where they
//! meet — real `IdentitySecurityResult`s from real IDENTITY-LAB fixtures are
//! converted into the product block, so a drift between engine vocabulary and
//! report vocabulary fails a test instead of quietly mislabelling a report.

use dare_identity_security::canonical::bind;
use dare_identity_security::corpus::builtin_corpus;
use dare_identity_security::model::IdentitySecurityScenario;
use dare_identity_security::result::{run_scenario, IdentitySecurityResult};
use dare_identity_security::simulated::SimulatedAdapter;
use dare_identity_security::trials::TrialPlan;
use dare_product::{
    assert_bounded_identity_security_claim, build_identity_security_metadata,
    IdentityScenarioOutcome, IdentitySurfaceAvailability, IdentitySurfaceState,
    IDENTITY_SECURITY_BOUNDED_INCONCLUSIVE_NOTE, IDENTITY_SECURITY_BOUNDED_PASS_NOTE,
    IDENTITY_SECURITY_BOUNDED_VIOLATION_NOTE,
};

const PROFILE: &str = "identity-security-baseline-2026";

fn scenario(id: &str) -> IdentitySecurityScenario {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("crates/dare-identity-security/tests/fixtures/scenarios")
        .join(format!("{}.json", id.to_ascii_lowercase()));
    let raw = std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    let value: serde_json::Value = serde_json::from_slice(&raw).expect("scenario parses");
    dare_identity_security::schema::validate_scenario_document(&value).expect("scenario validates");
    let scenario: IdentitySecurityScenario =
        serde_json::from_value(value).expect("scenario decodes");
    scenario.validate().expect("scenario is structurally valid");
    scenario
}

fn run(id: &str) -> IdentitySecurityResult {
    let scenario = scenario(id);
    // Identity binding is what refuses a substituted principal set or ceiling,
    // so it runs here for the same reason the CLI runs it: before anything is
    // observed.
    bind(&scenario).expect("binds");
    let corpus = builtin_corpus().expect("corpus loads");
    let entry = scenario
        .vector
        .as_ref()
        .map(|vector| corpus.require(&vector.corpus_id).expect("vector").clone());

    run_scenario(
        &scenario,
        entry.as_ref(),
        &SimulatedAdapter::new(),
        TrialPlan::from_scenario(&scenario).expect("plan"),
    )
    .expect("runs")
}

/// Convert an engine result into the product layer's neutral record.
///
/// The surface comes from the invariant's own declared surface rather than from
/// a string, which is what keeps a report row from silently reading "not
/// tested" when the taxonomy moves.
fn outcome_for(result: &IdentitySecurityResult) -> IdentityScenarioOutcome {
    IdentityScenarioOutcome {
        scenario_id: result.scenario_id.clone(),
        property_id: result.property_id.clone(),
        surface: result.invariant.surface().as_str().to_owned(),
        invariant: result.invariant.as_str().to_owned(),
        mode: result.mode.as_str().to_owned(),
        synthetic: result.synthetic,
        verdict: result.verdict.as_str().to_owned(),
        trials_planned: result.trials_planned,
        trials_executed: result.trials_executed,
        operations: result.operations(),
        authorization_decisions: result
            .trials
            .iter()
            .map(|trial| trial.authorization_decisions)
            .sum(),
        max_delegation_depth: result.max_delegation_depth().unwrap_or(0),
        violations: result.violations().len() as u32,
    }
}

#[test]
fn the_engine_surface_vocabulary_matches_the_report_vocabulary() {
    // If the engine ever emitted a surface the report does not know, that row
    // would silently read "not tested" for a surface that was in fact
    // exercised.
    use dare_identity_security::model::IdentityInvariantType;
    let known = dare_product::identity_security_metadata::IDENTITY_SURFACES;
    for invariant in IdentityInvariantType::all() {
        let surface = invariant.surface().as_str();
        assert!(
            known.contains(&surface),
            "{} reports surface `{surface}`, which the product layer does not know",
            invariant.as_str()
        );
    }
}

#[test]
fn a_passing_run_renders_the_bounded_pass_note() {
    let result = run("IDENTITY-LAB-001");
    assert_eq!(result.verdict.as_str(), "PASS");

    let metadata = build_identity_security_metadata(
        PROFILE,
        &[outcome_for(&result)],
        IdentitySurfaceAvailability::default(),
    )
    .expect("builds");

    assert_eq!(metadata.profile, PROFILE);
    assert_eq!(metadata.assurance_note, IDENTITY_SECURITY_BOUNDED_PASS_NOTE);
    assert_eq!(
        metadata.surfaces["PRINCIPAL_BINDING"],
        IdentitySurfaceState::Tested
    );
    assert_eq!(metadata.counts.violations, 0);
    assert_eq!(metadata.counts.state_changes, 0);
    assert_eq!(metadata.counts.external_egress_bytes, 0);
}

#[test]
fn a_violating_run_renders_the_violation_note_and_never_a_pass() {
    let result = run("IDENTITY-LAB-008");
    assert_eq!(result.verdict.as_str(), "FAIL");

    let metadata = build_identity_security_metadata(
        PROFILE,
        &[outcome_for(&result)],
        IdentitySurfaceAvailability::default(),
    )
    .expect("builds");

    assert_eq!(
        metadata.assurance_note,
        IDENTITY_SECURITY_BOUNDED_VIOLATION_NOTE
    );
    assert!(metadata.counts.violations > 0);
    assert_eq!(
        metadata.surfaces["TENANT_RESOURCE"],
        IdentitySurfaceState::Tested
    );
}

#[test]
fn an_inconclusive_run_is_never_rendered_as_a_pass() {
    let result = run("IDENTITY-LAB-016");
    assert_eq!(result.verdict.as_str(), "INCONCLUSIVE");

    let metadata = build_identity_security_metadata(
        PROFILE,
        &[outcome_for(&result)],
        IdentitySurfaceAvailability::default(),
    )
    .expect("builds");

    assert_eq!(
        metadata.assurance_note,
        IDENTITY_SECURITY_BOUNDED_INCONCLUSIVE_NOTE
    );
    assert_ne!(metadata.assurance_note, IDENTITY_SECURITY_BOUNDED_PASS_NOTE);
    assert_eq!(
        metadata.surfaces["PRINCIPAL_BINDING"],
        IdentitySurfaceState::Inconclusive
    );
    assert_eq!(metadata.counts.inconclusive, 1);
}

#[test]
fn every_surface_is_reachable_from_the_shipped_labs() {
    // A surface no lab can reach would be permanently "not tested" in every
    // report, which is a coverage claim nobody could ever satisfy.
    let labs = [
        ("IDENTITY-LAB-001", "PRINCIPAL_BINDING"),
        ("IDENTITY-LAB-003", "DELEGATION"),
        ("IDENTITY-LAB-005", "PRIVILEGE"),
        ("IDENTITY-LAB-007", "TENANT_RESOURCE"),
        ("IDENTITY-LAB-011", "AUTHORIZATION_BINDING"),
    ];

    let outcomes: Vec<IdentityScenarioOutcome> = labs
        .iter()
        .map(|(lab, expected)| {
            let result = run(lab);
            let outcome = outcome_for(&result);
            assert_eq!(&outcome.surface, expected, "{lab}");
            outcome
        })
        .collect();

    let metadata = build_identity_security_metadata(
        PROFILE,
        &outcomes,
        IdentitySurfaceAvailability::default(),
    )
    .expect("builds");

    for (_, surface) in labs {
        assert_eq!(
            metadata.surfaces[surface],
            IdentitySurfaceState::Tested,
            "{surface}"
        );
    }
    assert_eq!(metadata.counts.scenarios, 5);
    assert_eq!(metadata.assurance_note, IDENTITY_SECURITY_BOUNDED_PASS_NOTE);
}

#[test]
fn a_synthetic_run_is_disclosed_as_synthetic_in_the_report() {
    let result = run("IDENTITY-LAB-001");
    let metadata = build_identity_security_metadata(
        PROFILE,
        &[outcome_for(&result)],
        IdentitySurfaceAvailability::default(),
    )
    .expect("builds");

    assert!(metadata.scenarios[0].synthetic);
    assert!(metadata
        .limitations
        .iter()
        .any(|line| line.contains("synthetic and describe a reference agent")));
    assert!(metadata
        .limitations
        .iter()
        .any(|line| line.contains("never dispatched")));
    assert!(metadata
        .limitations
        .iter()
        .any(|line| line.contains("no token was parsed or validated")));
}

#[test]
fn the_rendered_block_carries_no_unbounded_claim() {
    let outcomes: Vec<IdentityScenarioOutcome> = ["IDENTITY-LAB-001", "IDENTITY-LAB-008"]
        .iter()
        .map(|lab| outcome_for(&run(lab)))
        .collect();

    let metadata = build_identity_security_metadata(
        PROFILE,
        &outcomes,
        IdentitySurfaceAvailability::default(),
    )
    .expect("builds");

    let rendered = serde_json::to_string(&metadata).expect("serializes");
    assert_bounded_identity_security_claim(&rendered).expect("the block is bounded");

    let lowered = rendered.to_lowercase();
    for banned in [
        "identity secure",
        "authorization secure",
        "no privilege escalation possible",
        "fully protected",
        "immune",
        "authzen compliant",
        "coaz compliant",
    ] {
        assert!(!lowered.contains(banned), "`{banned}` in the report block");
    }
}

#[test]
fn the_block_states_the_authority_relation_the_verdicts_rest_on() {
    let result = run("IDENTITY-LAB-005");
    let metadata = build_identity_security_metadata(
        PROFILE,
        &[outcome_for(&result)],
        IdentitySurfaceAvailability::default(),
    )
    .expect("builds");

    assert!(metadata
        .authority_relation
        .contains("effective_authority <= delegated_or_source_authority_ceiling"));
    assert!(metadata.credential_rule.contains("not delegated authority"));
    assert!(metadata.standards_note.contains("not conformance"));
}
