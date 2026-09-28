//! System-model admission and resolution rules (BLUEPRINT §4.5, task-012).
use dare_attack_path::{
    model::{admit_model_bytes, load_model, SYSTEM_MODEL_SCHEMA_V1_JSON},
    AttackPathError, EngineSlug, ModelRefusal, Refusal,
};
use serde_json::{json, Value};

fn base() -> Value {
    json!({
        "schema_version": "1",
        "model_id": "support-agent",
        "target_id": "support-agent",
        "target_version": "2026.09",
        "entities": [
            {"entity_id": "support", "type": "AGENT", "display_name": "Support agent"},
            {"entity_id": "crm-token", "type": "CREDENTIAL", "display_name": "CRM token",
             "security": {"privileged": true}},
            {"entity_id": "records-b", "type": "RESOURCE", "display_name": "Tenant B records",
             "security": {"tenant": "tenant-b", "sensitive": true}}
        ],
        "aliases": [
            {"engine": "tool", "local_id": "sut", "entity_id": "support"},
            {"engine": "identity", "local_id": "agent-1", "run": "0123456789ab", "entity_id": "support"}
        ],
        "entry_points": [{"entity_id": "support", "class": "LOW_PRIVILEGE_PRINCIPAL"}],
        "targets": [{"node_id": "node:resource:identity:0123456789ab:res-9", "class": "SENSITIVE_RESOURCE"}],
        "trust_boundaries": [{"boundary_id": "tenant-b-zone", "entity_ids": ["records-b"]}],
        "declared_edges": [
            {"type": "USES_CREDENTIAL", "source": "support", "target": "crm-token",
             "authority": {"principal": "support", "credential": "crm-token"},
             "status": "INFERRED", "rationale": "the deployment manifest mounts the token"}
        ]
    })
}

fn admit(value: &Value) -> Result<dare_attack_path::model::AdmittedModel, AttackPathError> {
    admit_model_bytes(&serde_json::to_vec(value).unwrap())
}

fn refusal(value: &Value) -> ModelRefusal {
    match admit(value) {
        Err(AttackPathError::Refused(Refusal::Model(r))) => r,
        other => panic!("expected a model refusal, got {other:?}"),
    }
}

#[test]
fn the_schema_compiles_and_the_base_model_is_admitted() {
    let schema: Value = serde_json::from_str(SYSTEM_MODEL_SCHEMA_V1_JSON).unwrap();
    jsonschema::options().build(&schema).unwrap();
    let model = admit(&base()).unwrap();
    assert!(model.digest.starts_with("sha256:") && model.digest.len() == 71);
    assert_eq!(model.entity("support").unwrap().0, 0);
}

#[test]
fn the_digest_ignores_key_order_and_whitespace_but_not_content() {
    let a = admit(&base()).unwrap().digest;
    let pretty = serde_json::to_vec_pretty(&base()).unwrap();
    assert_eq!(admit_model_bytes(&pretty).unwrap().digest, a);
    let mut changed = base();
    changed["target_version"] = json!("2026.10");
    assert_ne!(admit(&changed).unwrap().digest, a);
}

#[test]
fn rule_1_entities_are_unique_well_formed_and_safely_labelled() {
    let mut duplicate = base();
    duplicate["entities"][2]["entity_id"] = json!("support");
    assert_eq!(
        refusal(&duplicate),
        ModelRefusal::DuplicateEntity { entity: 2 }
    );
    let mut colon = base();
    colon["entities"][1]["entity_id"] = json!("crm:token");
    assert_eq!(
        refusal(&colon),
        ModelRefusal::UnusableEntityId { entity: 1 }
    );
    let mut secret = base();
    secret["entities"][0]["display_name"] = json!("Bearer abcdefgh1234");
    assert_eq!(refusal(&secret), ModelRefusal::UnsafeLabel { entity: 0 });
}

#[test]
fn rule_2_an_alias_must_name_a_known_entity() {
    let mut model = base();
    model["aliases"][0]["entity_id"] = json!("nobody");
    assert_eq!(
        refusal(&model),
        ModelRefusal::AliasUnknownEntity { alias: 0 }
    );
}

#[test]
fn rule_3_one_local_id_maps_to_one_entity() {
    let mut twice = base();
    twice["aliases"]
        .as_array_mut()
        .unwrap()
        .push(json!({"engine": "tool", "local_id": "sut", "entity_id": "records-b"}));
    assert_eq!(refusal(&twice), ModelRefusal::ConflictingAlias { alias: 2 });
    // A run-less alias and a run-specific alias for the same local id may
    // not point at different entities.
    let mut overlap = base();
    overlap["aliases"]
        .as_array_mut()
        .unwrap()
        .push(json!({"engine": "identity", "local_id": "agent-1", "entity_id": "records-b"}));
    assert_eq!(
        refusal(&overlap),
        ModelRefusal::ConflictingAlias { alias: 2 }
    );
    // …but may agree, and then the run-specific one is found first.
    let mut agree = base();
    agree["aliases"]
        .as_array_mut()
        .unwrap()
        .push(json!({"engine": "identity", "local_id": "agent-1", "entity_id": "support"}));
    let model = admit(&agree).unwrap();
    assert_eq!(
        model.alias_for(EngineSlug::Identity, "0123456789ab", "agent-1"),
        Some(1)
    );
    assert_eq!(
        model.alias_for(EngineSlug::Identity, "ffffffffffff", "agent-1"),
        Some(2)
    );
    assert_eq!(
        model.alias_for(EngineSlug::Tool, "ffffffffffff", "sut"),
        Some(0)
    );
    assert_eq!(
        model.alias_for(EngineSlug::Rag, "ffffffffffff", "sut"),
        None
    );
}

#[test]
fn rule_5_a_designation_names_exactly_one_reference() {
    let mut both = base();
    both["entry_points"][0]["node_id"] = json!("node:agent:support");
    assert_eq!(
        refusal(&both),
        ModelRefusal::DesignationNeedsOneReference { designation: 0 }
    );
    let mut neither = base();
    neither["targets"][0] = json!({"class": "SENSITIVE_RESOURCE"});
    assert_eq!(
        refusal(&neither),
        ModelRefusal::DesignationNeedsOneReference { designation: 0 }
    );
    let mut wrong_side = base();
    wrong_side["targets"][0]["class"] = json!("PEER_AGENT");
    assert!(matches!(refusal(&wrong_side), ModelRefusal::Invalid(_)));
}

#[test]
fn rule_6_declared_edges_carry_their_justification_and_known_entities() {
    let mut no_rationale = base();
    no_rationale["declared_edges"][0]
        .as_object_mut()
        .unwrap()
        .remove("rationale");
    assert_eq!(
        refusal(&no_rationale),
        ModelRefusal::DeclaredEdgeWithoutRationale { edge: 0 }
    );
    let mut blank = base();
    blank["declared_edges"][0]["rationale"] = json!("   ");
    assert_eq!(
        refusal(&blank),
        ModelRefusal::DeclaredEdgeWithoutRationale { edge: 0 }
    );
    let mut untested = base();
    untested["declared_edges"][0]["status"] = json!("NOT_TESTED");
    assert_eq!(
        refusal(&untested),
        ModelRefusal::DeclaredEdgeWithoutReason { edge: 0 }
    );
    let mut unknown = base();
    unknown["declared_edges"][0]["target"] = json!("nobody");
    assert_eq!(
        refusal(&unknown),
        ModelRefusal::DeclaredEdgeUnknownEntity { edge: 0 }
    );
    let mut not_a_credential = base();
    not_a_credential["declared_edges"][0]["authority"]["credential"] = json!("records-b");
    assert_eq!(
        refusal(&not_a_credential),
        ModelRefusal::DeclaredEdgeUnknownEntity { edge: 0 }
    );
}

#[test]
fn trust_boundaries_name_known_entities_and_have_unique_ids() {
    let mut unknown = base();
    unknown["trust_boundaries"][0]["entity_ids"] = json!(["nobody"]);
    assert_eq!(
        refusal(&unknown),
        ModelRefusal::BoundaryUnknownEntity { boundary: 0 }
    );
    let mut duplicate = base();
    let copy = duplicate["trust_boundaries"][0].clone();
    duplicate["trust_boundaries"]
        .as_array_mut()
        .unwrap()
        .push(copy);
    assert!(matches!(refusal(&duplicate), ModelRefusal::Invalid(_)));
}

#[test]
fn limits_and_unknown_fields_are_refused() {
    let mut many = base();
    let alias = many["aliases"][0].clone();
    many["aliases"] = Value::Array(vec![alias; 10_001]);
    assert_eq!(refusal(&many), ModelRefusal::OverLimit("aliases"));
    let mut extra = base();
    extra["extra"] = json!(true);
    assert!(matches!(refusal(&extra), ModelRefusal::Invalid(_)));
    let deep = format!("{}{}", "[".repeat(70), "]".repeat(70));
    assert_eq!(
        match admit_model_bytes(deep.as_bytes()) {
            Err(AttackPathError::Refused(Refusal::Model(r))) => r,
            other => panic!("{other:?}"),
        },
        ModelRefusal::TooDeep
    );
}

#[test]
fn the_file_loader_refuses_links_and_oversize() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("model.json");
    std::fs::write(&path, serde_json::to_vec(&base()).unwrap()).unwrap();
    assert!(load_model(&path).is_ok());
    let big = dir.path().join("big.json");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(4 * 1024 * 1024 + 1)
        .unwrap();
    assert!(matches!(
        load_model(&big),
        Err(AttackPathError::Refused(Refusal::Model(
            ModelRefusal::TooLarge
        )))
    ));
    #[cfg(unix)]
    {
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(matches!(
            load_model(&link),
            Err(AttackPathError::Refused(Refusal::Model(
                ModelRefusal::Symlink
            )))
        ));
    }
}
