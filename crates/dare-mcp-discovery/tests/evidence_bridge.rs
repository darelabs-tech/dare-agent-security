//! Cycle 001 evidence bridge: vectors emit valid, round-trippable records.

use std::fs;
use std::path::PathBuf;

use dare_mcp_discovery::{
    emit_baseline_evidence, emit_completeness_evidence, emit_policy_evidence,
    emit_protocol_evidence, emit_redaction_evidence, DiscoveryInventory, DiscoveryObservation,
    DiscoveryTarget, EvidenceBridgeError, PolicyProfile, RedactionStrategy, EXTENSION_KEY,
    VECTOR_COMPLETENESS, VECTOR_POLICY, VECTOR_PROTOCOL, VECTOR_REDACTION,
};
use dare_security_evidence::{SecurityEvidence, Verdict};
use serde_json::Value;
use time::macros::datetime;

const CANARY_URL_USER: &str = "canaryUser_7f3a";
const CANARY_URL_PASS: &str = "canaryPass_7f3a";
const CANARY_BEARER: &str = "canaryBearer_7f3a";
const CURRENT_METHODS: &[&str] = &[
    "server/discover",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
];

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/discovery")
}

fn load_inventory(name: &str) -> DiscoveryInventory {
    let path = examples_dir().join(name);
    let raw = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", path.display());
    });
    serde_json::from_str(&raw).unwrap_or_else(|err| {
        panic!("{name} is not valid inventory JSON: {err}");
    })
}

fn pass_observation() -> DiscoveryObservation {
    let inventory = load_inventory("complete.json");
    DiscoveryObservation {
        target: inventory.target.clone(),
        observed_at: inventory.generated_at,
        inventory: Some(inventory),
        invoked_methods: CURRENT_METHODS
            .iter()
            .map(|method| (*method).to_owned())
            .collect(),
        policy_profile: PolicyProfile::Current2026_07_28,
        evaluation_error: None,
        started_at: datetime!(2026-08-18 14:59:00 UTC),
        recorded_at: datetime!(2026-08-18 15:00:02 UTC),
    }
}

fn assert_valid_round_trip(evidence: &SecurityEvidence) {
    dare_security_evidence::validate(evidence).expect("semantic validate");
    let json = serde_json::to_value(evidence).expect("serialize");
    dare_security_evidence::validate_instance(&json).expect("schema validate_instance");
    let decoded: SecurityEvidence = serde_json::from_value(json.clone()).expect("deserialize");
    dare_security_evidence::validate(&decoded).expect("round-trip semantic");
    let json2 = serde_json::to_value(&decoded).expect("serialize again");
    assert_eq!(json, json2);
    assert_eq!(
        json["schema"]["id"],
        Value::String("https://darelabs.tech/schemas/evidence".to_owned())
    );
    assert_eq!(json["schema"]["version"], Value::String("1.0.0".to_owned()));
    let extensions = json["extensions"].as_object().expect("extensions object");
    assert!(
        extensions.keys().all(|key| key.contains('.')),
        "extension keys must be namespaced: {extensions:?}"
    );
    assert!(extensions.contains_key(EXTENSION_KEY));
    assert!(json["hashes"][0]["value"]
        .as_str()
        .is_some_and(|digest| digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())));
}

fn assert_no_canary(label: &str, value: &Value) {
    let rendered = value.to_string();
    for canary in [CANARY_URL_USER, CANARY_URL_PASS, CANARY_BEARER] {
        assert!(
            !rendered.contains(canary),
            "{label} leaked canary `{canary}`: {rendered}"
        );
    }
}

#[test]
fn complete_inventory_emits_four_valid_pass_records() {
    let records = emit_baseline_evidence(&pass_observation()).expect("emit");
    assert_eq!(records.len(), 4);
    assert_eq!(records[0].vector.id, VECTOR_PROTOCOL);
    assert_eq!(records[1].vector.id, VECTOR_POLICY);
    assert_eq!(records[2].vector.id, VECTOR_COMPLETENESS);
    assert_eq!(records[3].vector.id, VECTOR_REDACTION);
    for record in &records {
        assert_eq!(record.verdict, Verdict::Pass);
        assert_valid_round_trip(record);
    }
}

#[test]
fn protocol_fail_when_revision_is_unsupported() {
    let mut observation = pass_observation();
    if let Some(inventory) = observation.inventory.as_mut() {
        inventory.protocol.revision = "1999-01-01".to_owned();
    }
    let evidence = emit_protocol_evidence(&observation).expect("emit");
    assert_eq!(evidence.verdict, Verdict::Fail);
    assert_valid_round_trip(&evidence);
}

#[test]
fn protocol_fail_when_legacy_selected_under_current_profile() {
    let mut observation = pass_observation();
    if let Some(inventory) = observation.inventory.as_mut() {
        inventory.protocol.revision = "2024-11-05".to_owned();
    }
    let evidence = emit_protocol_evidence(&observation).expect("emit");
    assert_eq!(evidence.verdict, Verdict::Fail);
    assert_valid_round_trip(&evidence);
}

#[test]
fn protocol_inconclusive_when_revision_is_empty() {
    let mut observation = pass_observation();
    if let Some(inventory) = observation.inventory.as_mut() {
        inventory.protocol.revision.clear();
    }
    let evidence = emit_protocol_evidence(&observation).expect("emit");
    assert_eq!(evidence.verdict, Verdict::Inconclusive);
    assert_valid_round_trip(&evidence);
}

#[test]
fn policy_fail_when_non_allowlisted_method_was_invoked() {
    let mut observation = pass_observation();
    observation.invoked_methods.push("tools/call".to_owned());
    let evidence = emit_policy_evidence(&observation).expect("emit");
    assert_eq!(evidence.verdict, Verdict::Fail);
    assert_valid_round_trip(&evidence);
}

#[test]
fn completeness_fail_for_partial_inventory() {
    let inventory = load_inventory("partial.json");
    let observation = DiscoveryObservation {
        target: inventory.target.clone(),
        observed_at: inventory.generated_at,
        inventory: Some(inventory),
        invoked_methods: CURRENT_METHODS
            .iter()
            .map(|method| (*method).to_owned())
            .collect(),
        policy_profile: PolicyProfile::Current2026_07_28,
        evaluation_error: None,
        started_at: datetime!(2026-08-18 15:04:00 UTC),
        recorded_at: datetime!(2026-08-18 15:05:02 UTC),
    };
    let evidence = emit_completeness_evidence(&observation).expect("emit");
    assert_eq!(evidence.verdict, Verdict::Fail);
    assert_valid_round_trip(&evidence);
}

#[test]
fn redaction_fail_does_not_copy_raw_credentials() {
    let mut observation = pass_observation();
    let canary_url = format!("https://{CANARY_URL_USER}:{CANARY_URL_PASS}@mcp.example.test/mcp");
    if let Some(inventory) = observation.inventory.as_mut() {
        inventory.target.id = canary_url.clone();
        inventory.target.endpoint_fingerprint = Some(canary_url.clone());
        inventory.tools[0].description = Some(format!("Authorization: Bearer {CANARY_BEARER}"));
    }
    observation.target = DiscoveryTarget {
        id: canary_url,
        display_name: Some("synthetic rental lab".to_owned()),
        endpoint_fingerprint: Some(format!(
            "https://{CANARY_URL_USER}:{CANARY_URL_PASS}@mcp.example.test/mcp"
        )),
    };

    let evidence = emit_redaction_evidence(&observation).expect("emit");
    assert_eq!(evidence.verdict, Verdict::Fail);
    assert_valid_round_trip(&evidence);
    let json = serde_json::to_value(&evidence).expect("json");
    assert_no_canary("redaction fail evidence", &json);
    assert_ne!(evidence.target.id, "");
    assert!(!evidence.target.id.contains(CANARY_URL_USER));
}

#[test]
fn missing_inventory_is_inconclusive_not_pass() {
    let observation = DiscoveryObservation {
        target: DiscoveryTarget {
            id: "synthetic-rental-mcp".to_owned(),
            display_name: Some("synthetic rental lab".to_owned()),
            endpoint_fingerprint: Some("mcp.example.test/mcp".to_owned()),
        },
        inventory: None,
        invoked_methods: Vec::new(),
        policy_profile: PolicyProfile::Current2026_07_28,
        evaluation_error: None,
        started_at: datetime!(2026-08-18 14:59:00 UTC),
        observed_at: datetime!(2026-08-18 15:00:00 UTC),
        recorded_at: datetime!(2026-08-18 15:00:02 UTC),
    };
    let records = emit_baseline_evidence(&observation).expect("emit");
    assert_eq!(records.len(), 4);
    for record in &records {
        assert_eq!(record.verdict, Verdict::Inconclusive);
        assert_valid_round_trip(record);
    }
}

#[test]
fn evaluation_error_without_observation_is_error_not_pass() {
    let observation = DiscoveryObservation {
        target: DiscoveryTarget {
            id: "synthetic-rental-mcp".to_owned(),
            display_name: None,
            endpoint_fingerprint: None,
        },
        inventory: None,
        invoked_methods: Vec::new(),
        policy_profile: PolicyProfile::Current2026_07_28,
        evaluation_error: Some("transport timeout".to_owned()),
        started_at: datetime!(2026-08-18 14:59:00 UTC),
        observed_at: datetime!(2026-08-18 15:00:00 UTC),
        recorded_at: datetime!(2026-08-18 15:00:02 UTC),
    };
    let records = emit_baseline_evidence(&observation).expect("emit");
    for record in &records {
        assert_eq!(record.verdict, Verdict::Error);
        assert_valid_round_trip(record);
        assert!(record
            .observed
            .description
            .as_deref()
            .is_some_and(|text| !text.trim().is_empty()));
    }
}

#[test]
fn invalid_timestamps_are_rejected() {
    let mut observation = pass_observation();
    observation.recorded_at = datetime!(2026-08-18 14:00:00 UTC);
    let err = emit_protocol_evidence(&observation).expect_err("timestamps");
    assert_eq!(err, EvidenceBridgeError::InvalidTimestamps);
}

#[test]
fn redaction_inconclusive_when_metadata_is_incoherent() {
    let mut observation = pass_observation();
    if let Some(inventory) = observation.inventory.as_mut() {
        inventory.redaction.applied = true;
        inventory.redaction.strategy = RedactionStrategy::None;
    }
    let evidence = emit_redaction_evidence(&observation).expect("emit");
    assert_eq!(evidence.verdict, Verdict::Inconclusive);
    assert_valid_round_trip(&evidence);
}

#[test]
fn mcp_details_stay_in_namespaced_extensions() {
    let evidence = emit_protocol_evidence(&pass_observation()).expect("emit");
    assert!(evidence.target.protocol.is_none());
    assert!(evidence.target.protocol_version.is_none());
    let json = serde_json::to_value(&evidence).expect("json");
    let top = json.as_object().expect("object");
    assert!(!top.contains_key("mcp"));
    assert!(!top.contains_key("revision"));
    assert!(json["extensions"][EXTENSION_KEY]["protocol_revision"].is_string());
}

#[test]
fn evidence_crate_domain_is_untouched_by_this_module() {
    let manifest = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dare-security-evidence/Cargo.toml"
    ));
    assert!(!manifest.contains("dare-mcp-discovery"));
}
