//! Cycle 017 product-reporting integration.
//!
//! `dare-product` stays protocol-neutral: it takes plain outcome records rather
//! than the engine's types. That keeps the layers apart, but it also means
//! nothing inside either crate proves the two agree. This suite is where they
//! meet — real `RagSecurityResult`s from real RAG-LAB fixtures are converted
//! into the product block, so a drift between engine vocabulary and report
//! vocabulary fails a test instead of quietly mislabelling a report.

use dare_product::{
    assert_bounded_rag_security_claim, build_rag_security_metadata, RagScenarioOutcome,
    RagSurfaceAvailability, RagSurfaceState, RAG_SECURITY_BOUNDED_INCONCLUSIVE_NOTE,
    RAG_SECURITY_BOUNDED_PASS_NOTE, RAG_SECURITY_BOUNDED_VIOLATION_NOTE, RAG_SURFACES,
};
use dare_rag_security::canonical::bind;
use dare_rag_security::corpus::builtin_corpus;
use dare_rag_security::model::RagSecurityScenario;
use dare_rag_security::result::{run_scenario, RagSecurityResult};
use dare_rag_security::simulated::SimulatedAdapter;
use dare_rag_security::trials::TrialPlan;

const PROFILE: &str = "rag-security-baseline-2026";

fn scenario(id: &str) -> RagSecurityScenario {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("crates/dare-rag-security/tests/fixtures/scenarios")
        .join(format!("{}.json", id.to_ascii_lowercase()));
    let raw = std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    let value: serde_json::Value = serde_json::from_slice(&raw).expect("scenario parses");
    dare_rag_security::schema::validate_scenario_document(&value).expect("scenario validates");
    let scenario: RagSecurityScenario = serde_json::from_value(value).expect("scenario decodes");
    scenario.validate().expect("scenario is structurally valid");
    scenario
}

fn run(id: &str) -> RagSecurityResult {
    let scenario = scenario(id);
    // Binding is what refuses a substituted document, chunk or policy, so it
    // runs here for the same reason the CLI runs it: before anything is
    // observed.
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
fn outcome_for(result: &RagSecurityResult) -> RagScenarioOutcome {
    RagScenarioOutcome {
        scenario_id: result.scenario_id.clone(),
        property_id: result.property_id.as_str().to_owned(),
        surface: result.invariant.surface().as_str().to_owned(),
        invariant: result.invariant.as_str().to_owned(),
        mode: result.mode.as_str().to_owned(),
        synthetic: result.synthetic,
        verdict: result.verdict.as_str().to_owned(),
        trials_planned: result.trials_planned,
        trials_executed: result.trials_executed,
        queries: result.queries(),
        results: result.results(),
        violations: result.violations().len() as u32,
    }
}

#[test]
fn the_engine_surface_vocabulary_matches_the_report_vocabulary() {
    // The drift this catches: an engine surface the report has no row for
    // would be dropped silently, and every scenario on it would vanish from
    // the coverage table while still appearing to have run.
    for lab in [
        "RAG-LAB-001",
        "RAG-LAB-004",
        "RAG-LAB-008",
        "RAG-LAB-012",
        "RAG-LAB-014",
        "RAG-LAB-016",
        "RAG-LAB-020",
    ] {
        let outcome = outcome_for(&run(lab));
        assert!(
            RAG_SURFACES.contains(&outcome.surface.as_str()),
            "{lab} reports surface `{}`, which the product layer has no row for",
            outcome.surface
        );
    }
}

#[test]
fn the_labs_between_them_reach_every_surface_the_report_can_show() {
    // The mirror of the test above. A report row nothing ever fills would
    // render "not tested" forever while looking like a covered surface.
    let mut reached: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for index in 1..=22 {
        reached.insert(outcome_for(&run(&format!("RAG-LAB-{index:03}"))).surface);
    }

    for surface in RAG_SURFACES {
        assert!(
            reached.contains(surface),
            "no lab ever reports surface {surface}"
        );
    }
}

#[test]
fn a_clean_run_renders_the_bounded_pass_wording_and_nothing_stronger() {
    let outcome = outcome_for(&run("RAG-LAB-001"));
    assert_eq!(outcome.verdict, "PASS");

    let metadata =
        build_rag_security_metadata(PROFILE, &[outcome], RagSurfaceAvailability::default())
            .expect("builds");

    assert_eq!(metadata.assurance_note, RAG_SECURITY_BOUNDED_PASS_NOTE);
    assert!(metadata.assurance_note.contains("finite-corpus result"));
    assert_bounded_rag_security_claim(&serde_json::to_string(&metadata).expect("serializes"))
        .expect("the whole block is bounded");
}

#[test]
fn an_observed_violation_renders_the_violation_wording() {
    let outcome = outcome_for(&run("RAG-LAB-002"));
    assert_eq!(outcome.verdict, "FAIL");
    assert!(outcome.violations > 0);

    let metadata =
        build_rag_security_metadata(PROFILE, &[outcome], RagSurfaceAvailability::default())
            .expect("builds");

    assert_eq!(metadata.assurance_note, RAG_SECURITY_BOUNDED_VIOLATION_NOTE);
    assert_eq!(
        metadata.surfaces["DOCUMENT_ISOLATION"],
        RagSurfaceState::Tested
    );
    // A finding on one surface says nothing about the other five.
    assert_eq!(
        metadata.surfaces["PROVENANCE"],
        RagSurfaceState::NotTested,
        "a violation on one surface marked another as exercised"
    );
}

#[test]
fn an_undecided_run_never_reaches_the_pass_wording() {
    // The failure mode the whole coverage contract exists to prevent, checked
    // one layer further out: a run that decided nothing must not produce a
    // report that reads like a clean one.
    let outcome = outcome_for(&run("RAG-LAB-021"));
    assert_eq!(outcome.verdict, "INCONCLUSIVE");

    let metadata =
        build_rag_security_metadata(PROFILE, &[outcome], RagSurfaceAvailability::default())
            .expect("builds");

    assert_eq!(
        metadata.assurance_note,
        RAG_SECURITY_BOUNDED_INCONCLUSIVE_NOTE
    );
    assert_ne!(metadata.assurance_note, RAG_SECURITY_BOUNDED_PASS_NOTE);
    assert_eq!(
        metadata.surfaces["DOCUMENT_ISOLATION"],
        RagSurfaceState::Inconclusive
    );
}

#[test]
fn the_counts_carried_into_the_report_are_the_ones_the_engine_measured() {
    // A report whose numbers were recomputed from a different source could
    // disagree with the artifact it claims to summarize.
    let result = run("RAG-LAB-001");
    let outcome = outcome_for(&result);

    assert_eq!(outcome.trials_executed, result.trials_executed);
    assert_eq!(outcome.queries, result.queries());
    assert_eq!(outcome.results, result.results());

    let metadata = build_rag_security_metadata(
        PROFILE,
        std::slice::from_ref(&outcome),
        RagSurfaceAvailability::default(),
    )
    .expect("builds");

    assert_eq!(metadata.counts.trials, result.trials_executed);
    assert_eq!(metadata.counts.queries, result.queries());
    assert_eq!(metadata.counts.results, result.results());
    assert_eq!(metadata.counts.documents_indexed, 0);
    assert_eq!(metadata.counts.embeddings_computed, 0);
    assert_eq!(metadata.counts.external_egress_bytes, 0);
}

#[test]
fn no_rendered_block_from_any_lab_carries_a_canary_or_a_reachable_target() {
    // The report is the last place content can escape, and the place most
    // likely to quote what leaked.
    for index in 1..=22 {
        let lab = format!("RAG-LAB-{index:03}");
        let outcome = outcome_for(&run(&lab));
        let metadata =
            build_rag_security_metadata(PROFILE, &[outcome], RagSurfaceAvailability::default())
                .expect("builds");
        let rendered = serde_json::to_string(&metadata).expect("serializes");

        for marker in [
            "DARE-SYNTHETIC-CANARY-",
            "sk-live-",
            "-----BEGIN",
            "Bearer ey",
            "example.invalid",
        ] {
            assert!(
                !rendered.contains(marker),
                "{lab} rendered `{marker}` into the report block"
            );
        }

        // The block's own `schema_id` names a contract and is never resolved.
        // Any other scheme would be something a reader's tooling could follow.
        for (index, _) in rendered.match_indices("://") {
            let from = rendered[..index].rfind(|c: char| c.is_whitespace() || c == '"');
            let occurrence = &rendered[from.map_or(0, |at| at + 1)..];
            assert!(
                occurrence.starts_with("https://darelabs.tech/schemas/"),
                "{lab} rendered a reachable target: {}",
                &occurrence[..occurrence.len().min(80)]
            );
        }

        assert_bounded_rag_security_claim(&rendered).expect("bounded");
    }
}
