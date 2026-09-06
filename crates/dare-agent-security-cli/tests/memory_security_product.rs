//! Cycle 016 product-reporting integration.
//!
//! `dare-product` stays protocol-neutral: it takes plain outcome records rather
//! than the engine's types. That keeps the layers apart, but it also means
//! nothing inside either crate proves the two agree. This suite is where they
//! meet — real `MemorySecurityResult`s from real MEMORY-LAB fixtures are
//! converted into the product block, so a drift between engine vocabulary and
//! report vocabulary fails a test instead of quietly mislabelling a report.

use dare_memory_security::canonical::bind;
use dare_memory_security::corpus::builtin_corpus;
use dare_memory_security::model::MemorySecurityScenario;
use dare_memory_security::result::{run_scenario, MemorySecurityResult};
use dare_memory_security::simulated::SimulatedAdapter;
use dare_memory_security::trials::TrialPlan;
use dare_product::{
    assert_bounded_memory_security_claim, build_memory_security_metadata, MemoryScenarioOutcome,
    MemorySurfaceAvailability, MemorySurfaceState, MEMORY_SECURITY_BOUNDED_INCONCLUSIVE_NOTE,
    MEMORY_SECURITY_BOUNDED_PASS_NOTE, MEMORY_SECURITY_BOUNDED_VIOLATION_NOTE,
};

const PROFILE: &str = "memory-security-baseline-2026";

fn scenario(id: &str) -> MemorySecurityScenario {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("crates/dare-memory-security/tests/fixtures/scenarios")
        .join(format!("{}.json", id.to_ascii_lowercase()));
    let raw = std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    let value: serde_json::Value = serde_json::from_slice(&raw).expect("scenario parses");
    dare_memory_security::schema::validate_scenario_document(&value).expect("scenario validates");
    let scenario: MemorySecurityScenario = serde_json::from_value(value).expect("scenario decodes");
    scenario.validate().expect("scenario is structurally valid");
    scenario
}

fn run(id: &str) -> MemorySecurityResult {
    let scenario = scenario(id);
    // Binding is what refuses a substituted store, item or policy, so it runs
    // here for the same reason the CLI runs it: before anything is observed.
    bind(&scenario).expect("binds");
    let corpus = builtin_corpus().expect("corpus loads");
    let entry = scenario
        .vector
        .as_ref()
        .and_then(|vector| corpus.get(&vector.corpus_id).cloned());

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
fn outcome_for(result: &MemorySecurityResult) -> MemoryScenarioOutcome {
    MemoryScenarioOutcome {
        scenario_id: result.scenario_id.clone(),
        property_id: result.property_id.as_str().to_owned(),
        surface: result.invariant.surface().as_str().to_owned(),
        invariant: result.invariant.as_str().to_owned(),
        mode: result.mode.as_str().to_owned(),
        synthetic: result.synthetic,
        verdict: result.verdict.as_str().to_owned(),
        trials_planned: result.trials_planned,
        trials_executed: result.trials_executed,
        recall_items: result.recall_items(),
        violations: result.violations().len() as u32,
    }
}

#[test]
fn the_engine_surface_vocabulary_matches_the_report_vocabulary() {
    // The drift this catches: an engine surface the report has no row for
    // would be dropped silently, and every scenario on it would vanish from
    // the coverage table while still appearing to have run.
    for lab in [
        "MEMORY-LAB-001",
        "MEMORY-LAB-004",
        "MEMORY-LAB-008",
        "MEMORY-LAB-014",
        "MEMORY-LAB-017",
    ] {
        let outcome = outcome_for(&run(lab));
        assert!(
            dare_product::memory_security_metadata::MEMORY_SURFACES
                .contains(&outcome.surface.as_str()),
            "{lab} reports surface `{}`, which the product layer has no row for",
            outcome.surface
        );
    }
}

#[test]
fn a_clean_run_renders_the_bounded_pass_wording_and_nothing_stronger() {
    let outcome = outcome_for(&run("MEMORY-LAB-001"));
    assert_eq!(outcome.verdict, "PASS");

    let metadata =
        build_memory_security_metadata(PROFILE, &[outcome], MemorySurfaceAvailability::default())
            .expect("builds");

    assert_eq!(metadata.assurance_note, MEMORY_SECURITY_BOUNDED_PASS_NOTE);
    assert!(metadata.assurance_note.contains("finite-corpus result"));
    assert_bounded_memory_security_claim(&serde_json::to_string(&metadata).expect("serializes"))
        .expect("the rendered block is bounded");
}

#[test]
fn a_violated_run_renders_the_violation_wording() {
    let result = run("MEMORY-LAB-004");
    assert_eq!(result.verdict.as_str(), "FAIL");

    let metadata = build_memory_security_metadata(
        PROFILE,
        &[outcome_for(&result)],
        MemorySurfaceAvailability::default(),
    )
    .expect("builds");

    assert_eq!(
        metadata.assurance_note,
        MEMORY_SECURITY_BOUNDED_VIOLATION_NOTE
    );
    assert!(metadata.counts.violations >= 1);
    assert_eq!(
        metadata.surfaces["TRUST_BOUNDARY"],
        MemorySurfaceState::Tested
    );
}

#[test]
fn an_inconclusive_run_is_never_reported_as_a_pass() {
    let result = run("MEMORY-LAB-021");
    assert_eq!(result.verdict.as_str(), "INCONCLUSIVE");

    let metadata = build_memory_security_metadata(
        PROFILE,
        &[outcome_for(&result)],
        MemorySurfaceAvailability::default(),
    )
    .expect("builds");

    assert_eq!(
        metadata.assurance_note,
        MEMORY_SECURITY_BOUNDED_INCONCLUSIVE_NOTE
    );
    assert_ne!(metadata.assurance_note, MEMORY_SECURITY_BOUNDED_PASS_NOTE);
    // The surface it touched is marked undecided rather than exercised.
    assert_eq!(
        metadata.surfaces["TENANT_PRINCIPAL"],
        MemorySurfaceState::Inconclusive
    );
}

#[test]
fn a_run_covering_every_surface_marks_all_five_as_tested() {
    // One lab per surface. The point is that five separate scenarios are
    // needed to fill the table: no single run can mark more than its own.
    let outcomes: Vec<MemoryScenarioOutcome> = [
        "MEMORY-LAB-001",
        "MEMORY-LAB-004",
        "MEMORY-LAB-008",
        "MEMORY-LAB-014",
        "MEMORY-LAB-017",
    ]
    .iter()
    .map(|lab| outcome_for(&run(lab)))
    .collect();

    let metadata =
        build_memory_security_metadata(PROFILE, &outcomes, MemorySurfaceAvailability::default())
            .expect("builds");

    for surface in dare_product::memory_security_metadata::MEMORY_SURFACES {
        assert_eq!(
            metadata.surfaces[surface],
            MemorySurfaceState::Tested,
            "{surface} was not marked as tested"
        );
    }
    assert_eq!(metadata.counts.scenarios, 5);
    assert_eq!(metadata.counts.state_changes, 0);
    assert_eq!(metadata.counts.external_egress_bytes, 0);
}

#[test]
fn a_single_scenario_leaves_the_other_four_surfaces_visibly_untested() {
    // The failure this prevents: four surfaces absent from the table reading
    // as nothing to report, rather than as nothing tried.
    let metadata = build_memory_security_metadata(
        PROFILE,
        &[outcome_for(&run("MEMORY-LAB-001"))],
        MemorySurfaceAvailability::default(),
    )
    .expect("builds");

    let untested = metadata
        .surfaces
        .values()
        .filter(|state| **state == MemorySurfaceState::NotTested)
        .count();
    assert_eq!(untested, 4);
    assert!(metadata
        .limitations
        .iter()
        .any(|note| note.contains("was not exercised")));
}

#[test]
fn the_report_block_never_carries_a_canary_or_a_credential() {
    let outcomes: Vec<MemoryScenarioOutcome> = (1..=22)
        .map(|index| outcome_for(&run(&format!("MEMORY-LAB-{index:03}"))))
        .collect();

    let metadata =
        build_memory_security_metadata(PROFILE, &outcomes, MemorySurfaceAvailability::default())
            .expect("builds");
    let serialized = serde_json::to_string(&metadata).expect("serializes");

    for marker in [
        "DARE-SYNTHETIC-CANARY-",
        "sk-live-",
        "-----BEGIN",
        "Bearer ey",
    ] {
        assert!(!serialized.contains(marker), "the block carried {marker}");
    }
}

#[test]
fn the_block_states_the_relation_and_the_cycle_017_boundary() {
    let metadata = build_memory_security_metadata(
        PROFILE,
        &[outcome_for(&run("MEMORY-LAB-001"))],
        MemorySurfaceAvailability::default(),
    )
    .expect("builds");

    assert!(metadata
        .memory_trust_relation
        .contains("stored_data != trusted_instruction"));
    assert!(metadata
        .scope_boundary_note
        .contains("Retrieval-augmented generation"));
    assert!(metadata
        .limitations
        .iter()
        .any(|note| note.contains("never written to any store")));
    assert!(metadata
        .limitations
        .iter()
        .any(|note| note.contains("logical time")));
}

#[test]
fn every_reported_verdict_is_one_the_engine_can_actually_produce() {
    // A report vocabulary that drifted from the engine's would render an
    // unknown verdict as neither a pass nor a finding.
    for index in 1..=22 {
        let outcome = outcome_for(&run(&format!("MEMORY-LAB-{index:03}")));
        assert!(
            matches!(
                outcome.verdict.as_str(),
                "PASS" | "FAIL" | "INCONCLUSIVE" | "ERROR"
            ),
            "MEMORY-LAB-{index:03} reported `{}`",
            outcome.verdict
        );
    }
}
