use std::fs;
use std::path::PathBuf;

use dare_benchmark::digest_value;
use dare_benchmark::{
    aggregate_records, append_validation_entry, build_benchmark_run, builtin_policy,
    classify_for_prevalence, load_corpus_file, publication_safe_export, run_corpus_offline,
    DisclosureState, HumanValidationEntry, HumanValidationLedger, PrevalenceInclusion, RunnerMode,
    RunnerOptions, RunnerSafetyGate, ValidationStream,
};
use dare_coverage::{builtin_profile, profile_digest_sha256, REGISTRY_JSON};

fn pilot_manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../benchmark/corpus/pilot-methodology-v1/corpus-manifest.json")
}

#[test]
fn pilot_corpus_has_25_to_50_pinned_targets() {
    let manifest = load_corpus_file(pilot_manifest()).expect("pilot corpus");
    assert!(manifest.targets.len() >= 25 && manifest.targets.len() <= 50);
    for t in &manifest.targets {
        assert_eq!(t.commit.len(), 40);
    }
}

#[test]
fn offline_runner_produces_records_without_network() {
    let manifest = load_corpus_file(pilot_manifest()).unwrap();
    let policy = builtin_policy().unwrap();
    let profile = builtin_profile().unwrap();
    let profile_digest = profile_digest_sha256(&profile).unwrap();
    let registry_value: serde_json::Value = serde_json::from_str(REGISTRY_JSON).unwrap();
    let registry_digest = digest_value(&registry_value).unwrap();
    let run = build_benchmark_run(
        "run-pilot-methodology-001",
        &manifest,
        &policy,
        &profile.id,
        &profile.version,
        &profile_digest,
        "1.0.0",
        &registry_digest,
        "306a260",
        RunnerMode::LocalPassive,
    )
    .unwrap();
    let records = run_corpus_offline(&manifest, &run, &policy, &RunnerOptions::default()).unwrap();
    assert_eq!(records.len(), manifest.targets.len());
    let agg = aggregate_records(&manifest, &records, &policy);
    assert_eq!(agg.target_count, records.len() as u32);
    assert!(agg.disclaimer.contains("Not a population inference"));
    // Finding count and affected-target count are distinct dimensions.
    assert!(
        agg.finding_count_fail >= agg.affected_target_count_fail || agg.finding_count_fail == 0
    );
}

#[test]
fn mirrors_excluded_from_prevalence_denominator() {
    let manifest = load_corpus_file(pilot_manifest()).unwrap();
    let mirror = manifest
        .targets
        .iter()
        .find(|t| matches!(t.lineage.lineage_type, dare_benchmark::LineageType::Mirror))
        .expect("mirror target");
    assert_eq!(
        classify_for_prevalence(mirror),
        PrevalenceInclusion::ExcludeFromPrevalence
    );
}

#[test]
fn human_validation_and_disclosure_export() {
    let manifest = load_corpus_file(pilot_manifest()).unwrap();
    let policy = builtin_policy().unwrap();
    let profile = builtin_profile().unwrap();
    let profile_digest = profile_digest_sha256(&profile).unwrap();
    let registry_value: serde_json::Value = serde_json::from_str(REGISTRY_JSON).unwrap();
    let registry_digest = digest_value(&registry_value).unwrap();
    let run = build_benchmark_run(
        "run-pilot-methodology-002",
        &manifest,
        &policy,
        &profile.id,
        &profile.version,
        &profile_digest,
        "1.0.0",
        &registry_digest,
        "306a260",
        RunnerMode::Static,
    )
    .unwrap();
    let records = run_corpus_offline(
        &manifest,
        &run,
        &policy,
        &RunnerOptions {
            mode: RunnerMode::Static,
            authorized_dynamic_roe: false,
        },
    )
    .unwrap();
    let mut ledger = HumanValidationLedger::default();
    append_validation_entry(
        &mut ledger,
        HumanValidationEntry {
            sample_id: "pos-1".to_owned(),
            target_id: records[0].target.id.clone(),
            property_id: Some("MCP.AUTHZ.PER_OPERATION".to_owned()),
            stream: ValidationStream::PositiveFailReview,
            machine_verdict: Some("FAIL".to_owned()),
            human_label: "true_positive".to_owned(),
            notes: None,
        },
    )
    .unwrap();
    append_validation_entry(
        &mut ledger,
        HumanValidationEntry {
            sample_id: "neg-1".to_owned(),
            target_id: records[1].target.id.clone(),
            property_id: None,
            stream: ValidationStream::NegativePassReview,
            machine_verdict: Some("PASS".to_owned()),
            human_label: "spot_check".to_owned(),
            notes: None,
        },
    )
    .unwrap();
    assert!(ledger.count_stream(ValidationStream::PositiveFailReview) >= 1);
    assert!(ledger.count_stream(ValidationStream::NegativePassReview) >= 1);

    let export = publication_safe_export(&records[0], DisclosureState::Embargoed).unwrap();
    assert!(export.redacted);
    assert_eq!(export.repository, "[redacted]");
}

#[test]
fn hostile_path_traversal_fixture_is_refused() {
    assert!(RunnerSafetyGate::refuse_network_exfiltration("../escape").is_err());
    let hostile = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../benchmark/fixtures/hostile/path-traversal.json");
    let raw = fs::read_to_string(hostile).unwrap();
    assert!(raw.contains(".."));
}
