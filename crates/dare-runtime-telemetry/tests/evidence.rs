//! The evidence bridge and the coverage module (task-018).
mod support;

use dare_coverage::{
    multi_turn_security_profile, AssessmentProfile, CoverageStatus, EvidenceClass, ProfileProperty,
    RequirementLevel, SupportedMode,
};
use dare_runtime_telemetry::{
    coverage::{assessment_facts, coverage_report, coverage_rows, executions_document},
    evaluate::Rule,
    evidence_bridge::{bind_evidence, build_evidence, EXTENSION_NAMESPACE},
    limits::Bounds,
    result::{analyze, Mode, Run, RESULT_SCHEMA_JSON},
    schema::conforms,
};
use dare_security_evidence::{ObservationSource, SecurityEvidence, Verdict};
use support::*;

fn run(files: &[Vec<Sp>], with_policy: bool) -> Run {
    let inputs: Vec<_> = files.iter().map(|f| input(f)).collect();
    let p = policy();
    analyze(
        &inputs,
        with_policy.then_some(&p),
        &mapping(),
        Bounds::default(),
        Mode::Replay,
    )
    .unwrap()
}

fn bound(files: &[Vec<Sp>], with_policy: bool) -> (Run, Vec<SecurityEvidence>) {
    let mut r = run(files, with_policy);
    let records = bind_evidence(&mut r).unwrap();
    (r, records)
}

fn failing(t: &str) -> Vec<Sp> {
    let mut bad = good_trace(t);
    bad[1] = Sp::tool(t, "b", "a", "delete_all")
        .s("user.id", "user-7")
        .at(20);
    bad
}

fn orphaned(t: &str) -> Vec<Sp> {
    let mut o = good_trace(t);
    o[1].parent = Some(sid("f"));
    o
}

/// A profile over the nine properties this engine decides, plus one it does not.
fn profile() -> AssessmentProfile {
    let mut p = multi_turn_security_profile().unwrap();
    p.id = "runtime-telemetry-test".into();
    p.properties = Rule::ALL
        .iter()
        .map(|r| ProfileProperty {
            id: r.property_id().into(),
            requirement: RequirementLevel::Required,
        })
        .chain([ProfileProperty {
            id: "AGENT.GOAL.REFUSAL_PERSISTENCE".into(),
            requirement: RequirementLevel::Optional,
        }])
        .collect();
    p
}

#[test]
fn every_verdict_gives_a_valid_runtime_event_record() {
    let (r, records) = bound(&[good_trace("1"), failing("2"), orphaned("3")], true);
    let judged = r
        .result
        .properties
        .iter()
        .filter(|p| p.verdict.is_some())
        .count();
    assert_eq!(records.len(), judged);
    let verdicts: Vec<Verdict> = records.iter().map(|e| e.verdict).collect();
    assert!(verdicts.contains(&Verdict::Fail) && verdicts.contains(&Verdict::Inconclusive));
    for e in &records {
        dare_security_evidence::validate(e).unwrap_or_else(|x| panic!("{}: {x:?}", e.id));
        dare_security_evidence::validate_secret_safety(e).unwrap();
        assert_eq!(e.observed.source, ObservationSource::RuntimeEvent);
        let ext = e.extensions.as_ref().unwrap();
        assert!(ext.contains_key(EXTENSION_NAMESPACE));
        assert!(e.id.starts_with("runtime-telemetry-"));
    }
    // A passing run gives PASS records that validate too.
    let (_, pass) = bound(&[good_trace("1")], true);
    assert!(pass.iter().any(|e| e.verdict == Verdict::Pass));
    for e in &pass {
        dare_security_evidence::validate(e).unwrap();
    }
}

#[test]
fn ids_are_unique_bound_into_the_result_and_stable_across_runs() {
    let (r, records) = bound(&[good_trace("1"), failing("2")], true);
    let ids: std::collections::BTreeSet<&str> = records.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(ids.len(), records.len());
    for p in &r.result.properties {
        match p.verdict {
            Some(_) => {
                assert_eq!(p.evidence_ids.len(), 1);
                assert!(ids.contains(p.evidence_ids[0].as_str()));
            }
            None => assert!(p.evidence_ids.is_empty()),
        }
    }
    assert!(conforms(
        RESULT_SCHEMA_JSON,
        &serde_json::to_value(&r.result).unwrap()
    )
    .unwrap());
    // File order does not change a byte.
    let (r2, again) = bound(&[failing("2"), good_trace("1")], true);
    assert_eq!(
        serde_json::to_string(&records).unwrap(),
        serde_json::to_string(&again).unwrap()
    );
    assert_eq!(r.result.properties, r2.result.properties);
}

#[test]
fn timestamps_are_the_deciding_traces_span_times() {
    let mut late = failing("2");
    for s in &mut late {
        s.start += 1_000_000_000;
    }
    let (_, records) = bound(&[good_trace("1"), late], true);
    let b1 = records
        .iter()
        .find(|e| e.vector.id == "runtime-telemetry/B-1")
        .unwrap();
    assert_eq!(b1.verdict, Verdict::Fail);
    // Only the failing trace decides: its spans run from 1 s + 10 ns to 1 s + 40 ns.
    let started = b1.timestamps.started_at.unwrap();
    assert_eq!(started.unix_timestamp_nanos(), 1_000_000_010);
    assert_eq!(
        b1.timestamps.observed_at.unix_timestamp_nanos(),
        1_000_000_040
    );
    assert_eq!(b1.timestamps.recorded_at, b1.timestamps.observed_at);
}

#[test]
fn records_carry_no_attribute_value_and_neutralize_hostile_keys() {
    let jwt_key = "eyJhbGciOiJIUzI1NiJ9";
    let mut t = good_trace("1");
    t[0] = t[0]
        .clone()
        .s(jwt_key, "Bearer CANARY-VALUE-9f3b2a7c41d0")
        .s("note", "CANARY-TOOL-TEXT-51e7");
    let (r, records) = bound(&[t], true);
    let t1 = r
        .result
        .properties
        .iter()
        .find(|p| p.rule == Rule::Confidentiality)
        .unwrap();
    assert_eq!(t1.verdict, Some(Verdict::Fail));
    let json = serde_json::to_string(&records).unwrap();
    for planted in [
        "CANARY-VALUE-9f3b2a7c41d0",
        "CANARY-TOOL-TEXT-51e7",
        jwt_key,
        "user-7",
        "search",
        "api.example.com",
    ] {
        assert!(!json.contains(planted), "{planted} leaked");
    }
    assert!(
        json.contains("\"key-"),
        "the hostile key is written as a digest"
    );
}

#[test]
fn no_policy_run_records_only_the_telemetry_properties() {
    let (_, records) = bound(&[good_trace("1")], false);
    let vectors: Vec<&str> = records.iter().map(|e| e.vector.id.as_str()).collect();
    assert_eq!(vectors, ["runtime-telemetry/T-1", "runtime-telemetry/T-2"]);
    assert!(records.iter().all(|e| !e.preconditions[1].satisfied));
}

#[test]
fn the_executions_document_is_passive_trace_evidence() {
    let (r, _) = bound(&[good_trace("1"), failing("2")], true);
    let doc = executions_document(&r.result).unwrap();
    assert_eq!(doc.execution_mode, SupportedMode::Passive);
    assert_eq!(doc.evidence_class, EvidenceClass::Trace);
    assert_eq!(doc.executions.len(), Rule::ALL.len());
    doc.check(&assessment_facts(Some(&policy()))).unwrap();
    // Before the ids are bound a verdict has no evidence: refused.
    let unbound = run(&[good_trace("1")], true);
    assert!(executions_document(&unbound.result).is_err());
}

#[test]
fn coverage_rows_restate_the_engine_states_without_promotion() {
    let p = profile();
    // With a policy: judged rows are APPLICABLE, unexercised ones NOT_TESTED.
    let (r, _) = bound(&[good_trace("1")], true);
    let rows = coverage_rows(&r.result, &p);
    assert_eq!(rows.len(), p.properties.len());
    let row = |id: &str| rows.iter().find(|x| x.property_id == id).unwrap();
    let b1 = row(Rule::ToolAuthorization.property_id());
    assert_eq!(
        (b1.coverage_status, b1.verdict),
        (CoverageStatus::Applicable, Some(Verdict::Pass))
    );
    assert_eq!(b1.evidence_ids.len(), 1);
    let b2 = row(Rule::Approval.property_id());
    assert_eq!(
        (b2.coverage_status, b2.verdict),
        (CoverageStatus::NotTested, None)
    );
    let foreign = row("AGENT.GOAL.REFUSAL_PERSISTENCE");
    assert_eq!(foreign.coverage_status, CoverageStatus::NotTested);
    let report = coverage_report(&r.result, &p).unwrap();
    assert!(report.eligible >= report.tested);

    // Without a policy: behaviour rows are NOT_APPLICABLE with no verdict.
    let (r, _) = bound(&[good_trace("1")], false);
    for row in coverage_rows(&r.result, &p) {
        let rule = Rule::ALL
            .iter()
            .find(|x| x.property_id() == row.property_id);
        if let Some(rule) = rule.filter(|x| x.needs_policy()) {
            assert_eq!(
                (row.coverage_status, row.verdict),
                (CoverageStatus::NotApplicable, None),
                "{rule:?}"
            );
            assert!(row.rationale.contains("no_runtime_policy"));
        }
    }
    coverage_report(&r.result, &p).unwrap();
}

#[test]
fn the_facts_name_only_what_the_policy_says() {
    let facts = assessment_facts(None);
    assert!(facts.agent_present && facts.runtime_trace_present);
    assert!(!facts.human_approval_present);
    assert!(!facts.dynamic_authorization_allowed);
    assert_eq!(
        assessment_facts(Some(&policy())).human_approval_present,
        policy().approval.is_some()
    );
}

#[test]
fn build_and_bind_agree() {
    let r = run(&[good_trace("1"), failing("2")], true);
    let built = build_evidence(&r).unwrap();
    let mut r2 = r.clone();
    assert_eq!(bind_evidence(&mut r2).unwrap(), built);
}
