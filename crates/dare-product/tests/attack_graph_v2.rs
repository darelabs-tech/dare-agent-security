//! RF-16 per BQ-3 (a), task-042: a product fixture may name a v2 graph that
//! `validate attack-paths` wrote. The product validates it with
//! `dare_attack_graph::v2` only and writes it as the run's
//! `attack-graph.json`. Without the field, output is unchanged.
use std::{fs, path::Path};

use dare_product::{run_assessment, AssessOptions, ProductError};
use sha2::{Digest, Sha256};

const FIXTURE_V2: &str = include_str!("fixtures/attack-graph-v2.json");

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn assess(root: &Path, fixture: serde_json::Value) -> Result<std::path::PathBuf, ProductError> {
    fs::write(
        root.join("assessment-fixture.json"),
        serde_json::to_vec_pretty(&fixture).unwrap(),
    )
    .unwrap();
    run_assessment(&AssessOptions {
        target: root.to_path_buf(),
        config_path: None,
        confidential: true,
        offline: true,
        run_id: Some("run-attack-graph-v2".to_owned()),
    })
    .map(|outcome| outcome.run_dir)
}

fn sha256(path: &Path) -> String {
    format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
}

fn v1_facts() -> serde_json::Value {
    serde_json::from_slice(
        &fs::read(manifest_dir().join("../../fixtures/attack-graph/confused-deputy.json")).unwrap(),
    )
    .unwrap()
}

/// Digests of `attack-graph.json` recorded on the commit before this task
/// (`a3d6c06`), for a fixture without an attack graph and for a v1 facts
/// fixture. The new field must not move either.
const NO_GRAPH_DIGEST: &str = "637257e99c32c220d8030f2965a524c48a820ea1c71961fd4ee4d8e466b6def7";
const V1_FACTS_DIGEST: &str = "8f343a47aa85e5a4654bb01394f27d5397b92615d7571bc23516fef4a2921d57";

#[test]
fn without_the_field_the_attack_graph_artifact_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let run = assess(dir.path(), serde_json::json!({"limitations": ["k23"]})).unwrap();
    assert_eq!(sha256(&run.join("attack-graph.json")), NO_GRAPH_DIGEST);

    let dir = tempfile::tempdir().unwrap();
    let run = assess(
        dir.path(),
        serde_json::json!({"attack_graph_facts": v1_facts()}),
    )
    .unwrap();
    assert_eq!(sha256(&run.join("attack-graph.json")), V1_FACTS_DIGEST);
}

#[test]
fn a_v2_graph_is_validated_and_written_as_the_run_graph() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("out")).unwrap();
    fs::write(dir.path().join("out/attack-graph.json"), FIXTURE_V2).unwrap();
    let run = assess(
        dir.path(),
        serde_json::json!({"attack_graph_v2": "out/attack-graph.json"}),
    )
    .unwrap();
    let written: serde_json::Value =
        serde_json::from_slice(&fs::read(run.join("attack-graph.json")).unwrap()).unwrap();
    let source: serde_json::Value = serde_json::from_str(FIXTURE_V2).unwrap();
    assert_eq!(written, source);
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(run.join("summary.json")).unwrap()).unwrap();
    let text = summary["attack_path_summary"].as_str().unwrap();
    assert!(
        text.starts_with("Attack graph v2: 19 node(s), 21 edge(s)"),
        "{text}"
    );
    assert!(text.contains("analysis only (not executed)"), "{text}");
}

fn refused(fixture: serde_json::Value, setup: impl FnOnce(&Path)) -> String {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path());
    let err = assess(dir.path(), fixture).expect_err("refused");
    err.to_string()
}

#[test]
fn a_doctored_v2_graph_is_refused_without_echoing_it() {
    // An edge to a node the graph does not hold: invariant violation.
    let mut graph: serde_json::Value = serde_json::from_str(FIXTURE_V2).unwrap();
    graph["edges"][0]["target"] = "node:resource:PLANTED-9f1c".into();
    let message = refused(serde_json::json!({"attack_graph_v2": "g.json"}), |root| {
        fs::write(root.join("g.json"), serde_json::to_vec(&graph).unwrap()).unwrap()
    });
    assert!(message.contains("v2 graph validation failed"), "{message}");
    assert!(!message.contains("PLANTED"), "{message}");

    // Unknown fields: a v1 graph or anything else is not a v2 graph.
    let message = refused(serde_json::json!({"attack_graph_v2": "g.json"}), |root| {
        fs::write(root.join("g.json"), r#"{"PLANTED-field": 1}"#).unwrap()
    });
    assert!(message.contains("not a v2 attack graph"), "{message}");
    assert!(!message.contains("PLANTED"), "{message}");
}

#[test]
fn the_path_is_confined_to_the_target_and_exclusive_with_v1_facts() {
    for path in ["../outside.json", "/etc/hostname", "", "a/../../b.json"] {
        let message = refused(serde_json::json!({ "attack_graph_v2": path }), |_| {});
        assert!(
            message.contains("relative path inside the target"),
            "{path}: {message}"
        );
    }
    let message = refused(
        serde_json::json!({"attack_graph_v2": "g.json", "attack_graph_facts": v1_facts()}),
        |root| fs::write(root.join("g.json"), FIXTURE_V2).unwrap(),
    );
    assert!(message.contains("mutually exclusive"), "{message}");
    let message = refused(
        serde_json::json!({"attack_graph_v2": "missing.json"}),
        |_| {},
    );
    assert!(message.contains("not readable"), "{message}");
    #[cfg(unix)]
    {
        let message = refused(
            serde_json::json!({"attack_graph_v2": "link.json"}),
            |root| {
                fs::write(root.join("real.json"), FIXTURE_V2).unwrap();
                std::os::unix::fs::symlink(root.join("real.json"), root.join("link.json")).unwrap();
            },
        );
        assert!(message.contains("regular file"), "{message}");
    }
}

#[test]
fn the_product_does_not_depend_on_the_attack_path_engine() {
    let manifest = fs::read_to_string(manifest_dir().join("Cargo.toml")).unwrap();
    assert!(!manifest.contains("dare-attack-path"));
}
