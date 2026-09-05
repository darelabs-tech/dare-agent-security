//! Cycle 014 product-reporting integration.
//!
//! `dare-product` stays protocol-neutral: it takes plain outcome records rather
//! than the engine's types. That keeps the layers apart, but it also means
//! nothing inside either crate proves the two agree. This suite is where they
//! meet — real `ToolSecurityResult`s from real scenarios are converted into the
//! product block, so a drift between engine vocabulary and report vocabulary
//! fails a test instead of quietly mislabelling a report.

use dare_product::{
    assert_bounded_tool_security_claim, build_tool_security_metadata, SurfaceState,
    ToolScenarioOutcome, ToolSurfaceAvailability, TOOL_SECURITY_BOUNDED_PASS_NOTE,
};
use dare_tool_security::canonical::bind;
use dare_tool_security::corpus::builtin_corpus;
use dare_tool_security::model::{ToolFamily, ToolSecurityScenario};
use dare_tool_security::result::{run_scenario, ToolSecurityResult};
use dare_tool_security::simulated::ToolSimulatedAdapter;
use dare_tool_security::source::ScenarioClass;
use dare_tool_security::trials::ToolTrialPlan;

fn scenario(id: &str) -> ToolSecurityScenario {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/tool-security/scenarios")
        .join(format!("{id}.json"));
    let raw = std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    let value: serde_json::Value = serde_json::from_slice(&raw).expect("scenario parses");
    dare_tool_security::schema::validate_scenario_document(&value).expect("scenario validates");
    serde_json::from_value(value).expect("scenario decodes")
}

fn run(id: &str) -> ToolSecurityResult {
    let scenario = scenario(id);
    // Identity binding is what refuses a substituted vector, so it runs here
    // for the same reason the CLI runs it: before anything is observed.
    bind(&scenario).expect("binds");
    let corpus = builtin_corpus().expect("corpus loads");
    let entry = scenario
        .vector
        .as_ref()
        .map(|vector| corpus.require(&vector.corpus_id).expect("vector").clone());
    let lab = scenario.lab.clone().expect("lab behavior");

    run_scenario(
        &scenario,
        entry.as_ref(),
        &ToolSimulatedAdapter::new(lab),
        ToolTrialPlan::from_scenario(&scenario).expect("plan"),
    )
    .expect("runs")
}

/// Convert an engine result into the product layer's neutral record.
///
/// The surface is derived from the typed taxonomy rather than from the family
/// string, which is what keeps a report row from silently reading "not tested".
fn outcome_for(result: &ToolSecurityResult) -> ToolScenarioOutcome {
    let family: ToolFamily =
        serde_json::from_value(serde_json::Value::String(result.family.clone()))
            .expect("the recorded family decodes into the closed taxonomy");
    let surface = match family {
        ToolFamily::Poisoning(poisoning) => poisoning.surface_area().as_str(),
        ToolFamily::Misuse(misuse) => misuse.misuse_surface().as_str(),
    };

    ToolScenarioOutcome {
        scenario_id: result.scenario_id.clone(),
        property_id: result.property_id.clone(),
        class: match result.class {
            ScenarioClass::Poisoning => "POISONING".to_owned(),
            ScenarioClass::Misuse => "MISUSE".to_owned(),
        },
        family: result.family.clone(),
        surface: surface.to_owned(),
        invariant: result.invariant.as_str().to_owned(),
        mode: result.mode.as_str().to_owned(),
        synthetic: result.synthetic,
        verdict: result.verdict.as_str().to_owned(),
        trials_planned: result.trials_planned,
        trials_executed: result.trials_executed,
        tool_requests: result.tool_requests(),
        max_chain_depth: result.max_chain_depth().unwrap_or(0),
        violations: result.violations().len() as u32,
    }
}

#[test]
fn a_benign_assessment_reports_the_approved_bounded_wording() {
    let outcomes = ["TOOL-LAB-001", "TOOL-LAB-007"]
        .map(|id| outcome_for(&run(id)))
        .to_vec();
    let metadata = build_tool_security_metadata(
        "tool-security-baseline-2026",
        &outcomes,
        ToolSurfaceAvailability::default(),
    )
    .expect("metadata builds");

    assert_eq!(metadata.counts.violations, 0);
    assert_eq!(metadata.assurance_note, TOOL_SECURITY_BOUNDED_PASS_NOTE);
    assert!(metadata.assurance_note.starts_with(
        "No tool-security invariant violation was observed for the tested vectors under the \
         recorded conditions."
    ));
}

#[test]
fn poisoning_and_misuse_stay_separate_all_the_way_into_the_report() {
    let poisoning = outcome_for(&run("TOOL-LAB-002"));
    let metadata = build_tool_security_metadata(
        "tool-security-baseline-2026",
        &[poisoning],
        ToolSurfaceAvailability::default(),
    )
    .expect("metadata builds");
    assert_eq!(metadata.tool_poisoning, SurfaceState::Tested);
    assert_eq!(metadata.tool_misuse, SurfaceState::NotTested);

    let misuse = outcome_for(&run("TOOL-LAB-008"));
    let metadata = build_tool_security_metadata(
        "tool-security-baseline-2026",
        &[misuse],
        ToolSurfaceAvailability::default(),
    )
    .expect("metadata builds");
    assert_eq!(metadata.tool_poisoning, SurfaceState::NotTested);
    assert_eq!(metadata.tool_misuse, SurfaceState::Tested);
}

#[test]
fn every_scenario_maps_onto_a_surface_the_report_knows_about() {
    // The defect this catches: an engine family with no matching report row,
    // which would render as "not tested" for a surface that was tested.
    let ids = [
        "TOOL-LAB-001",
        "TOOL-LAB-002",
        "TOOL-LAB-003",
        "TOOL-LAB-004",
        "TOOL-LAB-005",
        "TOOL-LAB-006",
        "TOOL-LAB-007",
        "TOOL-LAB-008",
        "TOOL-LAB-009",
        "TOOL-LAB-010",
        "TOOL-LAB-011",
        "TOOL-LAB-012",
        "TOOL-LAB-013",
        "TOOL-LAB-014",
        "TOOL-LAB-015",
        "TOOL-LAB-018",
        "TOOL-LAB-019",
        "TOOL-LAB-020",
    ];

    for id in ids {
        let outcome = outcome_for(&run(id));
        let surface = outcome.surface.clone();
        let class = outcome.class.clone();
        let metadata = build_tool_security_metadata(
            "tool-security-baseline-2026",
            &[outcome],
            ToolSurfaceAvailability::default(),
        )
        .expect("metadata builds");

        let surfaces = if class == "POISONING" {
            &metadata.poisoning_surfaces
        } else {
            &metadata.misuse_surfaces
        };
        assert_eq!(
            surfaces.get(&surface).copied(),
            Some(SurfaceState::Tested),
            "{id} exercised {class}/{surface}, which the report did not mark tested"
        );
    }
}

#[test]
fn the_whole_corpus_assessed_at_once_covers_every_surface() {
    let ids = [
        "TOOL-LAB-002", // description poisoning
        "TOOL-LAB-004", // schema poisoning
        "TOOL-LAB-006", // output poisoning
        "TOOL-LAB-020", // metadata poisoning
        "TOOL-LAB-008", // selection misuse
        "TOOL-LAB-010", // argument misuse
        "TOOL-LAB-012", // chain misuse
        "TOOL-LAB-014", // invocation misuse
    ];
    let outcomes: Vec<_> = ids.iter().map(|id| outcome_for(&run(id))).collect();
    let metadata = build_tool_security_metadata(
        "tool-security-baseline-2026",
        &outcomes,
        ToolSurfaceAvailability::default(),
    )
    .expect("metadata builds");

    assert_eq!(metadata.tool_poisoning, SurfaceState::Tested);
    assert_eq!(metadata.tool_misuse, SurfaceState::Tested);
    assert_eq!(metadata.counts.scenarios, 8);
    assert!(metadata.counts.violations >= 8);

    // Annotation poisoning and output escalation are genuinely untested by this
    // selection, and the report says exactly that rather than staying silent.
    assert_eq!(
        metadata.poisoning_surfaces["ANNOTATIONS"],
        SurfaceState::NotTested
    );
    assert_eq!(
        metadata.misuse_surfaces["OUTPUT_ESCALATION"],
        SurfaceState::NotTested
    );
    assert!(metadata
        .limitations
        .iter()
        .any(|limit| limit == "Surface ANNOTATIONS was not exercised in this run."));
}

#[test]
fn an_inconclusive_scenario_never_reports_as_a_pass() {
    let outcome = outcome_for(&run("TOOL-LAB-015"));
    assert_eq!(outcome.verdict, "INCONCLUSIVE");
    let metadata = build_tool_security_metadata(
        "tool-security-baseline-2026",
        &[outcome],
        ToolSurfaceAvailability::default(),
    )
    .expect("metadata builds");
    assert_eq!(metadata.counts.inconclusive, 1);
    assert!(metadata.assurance_note.contains("is not a pass"));
    assert_ne!(metadata.assurance_note, TOOL_SECURITY_BOUNDED_PASS_NOTE);
}

#[test]
fn no_report_block_built_from_a_real_run_can_contain_an_unbounded_claim() {
    for id in [
        "TOOL-LAB-001",
        "TOOL-LAB-010",
        "TOOL-LAB-015",
        "TOOL-LAB-019",
    ] {
        let metadata = build_tool_security_metadata(
            "tool-security-baseline-2026",
            &[outcome_for(&run(id))],
            ToolSurfaceAvailability::default(),
        )
        .expect("metadata builds");
        let rendered = serde_json::to_string(&metadata).expect("serializes");
        assert_bounded_tool_security_claim(&rendered).unwrap_or_else(|err| panic!("{id}: {err}"));
    }
}

#[test]
fn independently_observed_violations_are_all_counted_in_the_report() {
    let outcome = outcome_for(&run("TOOL-LAB-008"));
    assert!(
        outcome.violations >= 2,
        "the vector crosses the boundary twice; the report must not count it once"
    );
    let metadata = build_tool_security_metadata(
        "tool-security-baseline-2026",
        &[outcome],
        ToolSurfaceAvailability::default(),
    )
    .expect("metadata builds");
    assert_eq!(metadata.counts.violations, metadata.scenarios[0].violations);
}
