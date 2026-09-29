//! `validate blast-radius` at the process boundary (tasks 021 and 022).
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use dare_attack_graph::v2::{graph_id_v2, AttackGraphV2};
use serde_json::{json, Value};

const FILES: [&str; 4] = ["blast-radius.json", "graph.dot", "graph.mmd", "summary.md"];

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dare-agent-security"))
}

fn bundles() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../dare-attack-path/tests/fixtures/bundles")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("binary runs")
}

/// The v2 graph `validate attack-paths` writes for one Cycle 023 bundle.
fn graph_of(root: &Path, bundle: &str) -> PathBuf {
    let out = root.join(format!("ap-{bundle}"));
    let result = run(&[
        "validate",
        "attack-paths",
        "--artifacts",
        bundles().join(bundle).to_str().unwrap(),
        "--output-dir",
        out.to_str().unwrap(),
    ]);
    assert!(matches!(result.status.code(), Some(0 | 2)), "{bundle}");
    out.join("attack-graph.json")
}

fn blast(graph: &Path, seeding: &[&str], extra: &[&str], out: &Path) -> Output {
    let mut args = vec![
        "validate",
        "blast-radius",
        "--graph",
        graph.to_str().unwrap(),
        "--output-dir",
        out.to_str().unwrap(),
    ];
    args.extend_from_slice(seeding);
    args.extend_from_slice(extra);
    run(&args)
}

fn read_graph(path: &Path) -> AttackGraphV2 {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

/// Writes `graph` sorted and resealed, as `validate attack-paths` would.
fn write_graph(path: &Path, mut graph: AttackGraphV2) {
    graph.nodes.sort_by(|a, b| a.id.cmp(&b.id));
    graph.edges.sort_by(|a, b| a.id.cmp(&b.id));
    graph.id = graph_id_v2(&graph).unwrap();
    fs::write(path, serde_json::to_vec_pretty(&graph).unwrap()).unwrap();
}

fn scenario(root: &Path, name: &str, value: Value) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    path
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

const USER_7: &str = "node:human:identity:569fbf2d8b1f:user-7";

#[test]
fn help_names_every_flag_and_offers_nothing_else() {
    let help = String::from_utf8(run(&["validate", "blast-radius", "--help"]).stdout).unwrap();
    let mut flags: Vec<&str> = help
        .split_whitespace()
        .filter(|w| w.starts_with("--"))
        .map(|w| w.trim_end_matches(','))
        .collect();
    flags.sort();
    flags.dedup();
    assert_eq!(
        flags,
        [
            "--compromise",
            "--graph",
            "--help",
            "--json",
            "--max-depth",
            "--max-states",
            "--output-dir",
            "--seed-entry-points",
        ]
    );
    assert!(help.contains("does not mean safe") && help.contains("not a ranking of risk"));
    for code in [
        "0  no target is EXPOSED",
        "2  a target is EXPOSED",
        "3  refusal",
    ] {
        assert!(help.contains(code), "{code}");
    }
    for forbidden in ["--url", "--exec", "--engine", "--token", "--execute"] {
        let out = run(&["validate", "blast-radius", forbidden, "x"]);
        assert_ne!(out.status.code(), Some(0), "{forbidden} accepted");
    }
}

#[test]
fn seeding_is_one_of_a_scenario_or_the_entry_points() {
    let root = tempfile::tempdir().unwrap();
    let graph = graph_of(root.path(), "identity");
    let out = root.path().join("out");
    let none = blast(&graph, &[], &[], &out);
    assert_eq!(none.status.code(), Some(3));
    let both = blast(
        &graph,
        &["--seed-entry-points", "--compromise", "x.json"],
        &[],
        &out,
    );
    assert_eq!(both.status.code(), Some(3));
    assert!(!out.exists());
}

#[test]
fn exit_0_writes_four_files_when_nothing_is_exposed() {
    let root = tempfile::tempdir().unwrap();
    // A2A: one peer agent seed, no target.
    let graph = graph_of(root.path(), "a2a");
    let out = root.path().join("out");
    let result = blast(&graph, &["--seed-entry-points"], &["--json"], &out);
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(names(&out), FILES);
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains(
        "\"schema_id\": \"https://darelabs.tech/schemas/blast-radius/v1/blast-radius.schema.json\""
    ));
    assert!(stdout.ends_with("1 seeds: 0 EXPOSED, 0 CONTAINED, 0 CONTAINMENT_UNKNOWN targets\n"));
}

#[test]
fn exit_2_when_a_target_is_exposed_or_a_search_is_truncated() {
    let root = tempfile::tempdir().unwrap();
    // Identity: the low-privilege user reaches the admin credential.
    let graph = graph_of(root.path(), "identity");
    let out = root.path().join("exposed");
    let result = blast(&graph, &["--seed-entry-points"], &[], &out);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(result.stdout).unwrap(),
        "1 seeds: 1 EXPOSED, 0 CONTAINED, 0 CONTAINMENT_UNKNOWN targets\n"
    );
    let doc: Value =
        serde_json::from_slice(&fs::read(out.join("blast-radius.json")).unwrap()).unwrap();
    assert_eq!(doc["seeds"][0]["targets"][0]["exposure"], "EXPOSED");
    assert_eq!(
        doc["seeds"][0]["targets"][0]["class"],
        "PRIVILEGED_CREDENTIAL"
    );
    // One state per search: truncated, and CONTAINMENT_UNKNOWN is not a pass.
    let out = root.path().join("cut");
    let result = blast(
        &graph,
        &["--seed-entry-points"],
        &["--max-states", "1"],
        &out,
    );
    assert_eq!(result.status.code(), Some(2));
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.ends_with(", truncated\n"), "{stdout}");
}

#[test]
fn exit_1_on_an_internal_write_failure() {
    let root = tempfile::tempdir().unwrap();
    let graph = graph_of(root.path(), "a2a");
    let out = root.path().join("out");
    // A directory where the first file must go: writing it fails, even as root.
    fs::create_dir_all(out.join("blast-radius.json")).unwrap();
    let result = blast(&graph, &["--seed-entry-points"], &[], &out);
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!out.join("summary.md").exists());
}

#[test]
fn a_scenario_names_its_seeds_and_lowers_the_bounds() {
    let root = tempfile::tempdir().unwrap();
    let graph = graph_of(root.path(), "identity");
    let id = read_graph(&graph).id;
    let compromise = scenario(
        root.path(),
        "leak.json",
        json!({
            "schema_version": "1",
            "scenario_id": "admin-credential-leak",
            "graph_id": id,
            "seeds": [{"node_id": "node:credential:identity:569fbf2d8b1f:cred-index-admin",
                       "kind": "CREDENTIAL_LEAK"}],
            "max_depth": 4
        }),
    );
    let out = root.path().join("out");
    let result = blast(
        &graph,
        &["--compromise", compromise.to_str().unwrap()],
        &[],
        &out,
    );
    // The leaked credential reaches the document, which is not a target.
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let doc: Value =
        serde_json::from_slice(&fs::read(out.join("blast-radius.json")).unwrap()).unwrap();
    assert_eq!(doc["scenario_id"], "admin-credential-leak");
    assert_eq!(doc["seeds"][0]["kind"], "CREDENTIAL_LEAK");
    assert_eq!(doc["seeds"][0]["structural"]["nodes_reached"], 2);
    assert_eq!(
        doc["bounds"]["max_depth"], 4,
        "the scenario lowers the default"
    );
    assert!(doc["scenario_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    let summary = fs::read_to_string(out.join("summary.md")).unwrap();
    assert!(summary.contains("## What this does not claim"));
}

#[test]
fn two_runs_give_byte_identical_files() {
    let root = tempfile::tempdir().unwrap();
    let graph = graph_of(root.path(), "identity");
    let (a, b) = (root.path().join("a"), root.path().join("b"));
    blast(&graph, &["--seed-entry-points"], &[], &a);
    blast(&graph, &["--seed-entry-points"], &[], &b);
    for file in FILES {
        assert_eq!(
            fs::read(a.join(file)).unwrap(),
            fs::read(b.join(file)).unwrap(),
            "{file}"
        );
    }
}

/// Asserts exit 3, nothing written, and no planted value in the message.
fn refused(graph: &Path, seeding: &[&str], extra: &[&str], canary: Option<&str>) {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("never");
    let result = blast(graph, seeding, extra, &out);
    let stderr = String::from_utf8_lossy(&result.stderr).into_owned();
    assert_eq!(result.status.code(), Some(3), "{stderr}");
    assert!(!out.exists(), "a refusal wrote output");
    assert!(stderr.starts_with("refused:"), "{stderr}");
    if let Some(canary) = canary {
        assert!(!stderr.contains(canary), "{stderr}");
    }
}

#[test]
fn refusal_corpus_graph_files() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let seeds = ["--seed-entry-points"];
    // Missing, symbolic link, too large, too deep, not a graph.
    refused(&root.join("missing.json"), &seeds, &[], None);
    let real = graph_of(root, "identity");
    let link = root.join("link.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    refused(&link, &seeds, &[], None);
    let large = root.join("large.json");
    fs::write(&large, vec![b' '; 16 * 1024 * 1024 + 1]).unwrap();
    refused(&large, &seeds, &[], None);
    let deep = root.join("deep.json");
    fs::write(&deep, format!("{}{}", "[".repeat(70), "]".repeat(70))).unwrap();
    refused(&deep, &seeds, &[], None);
    let other = root.join("other.json");
    fs::write(&other, r#"{"nodes":[],"CANARY-FIELD":1}"#).unwrap();
    refused(&other, &seeds, &[], Some("CANARY-FIELD"));
    // A graph edited after sealing.
    let mut graph: Value = serde_json::from_slice(&fs::read(&real).unwrap()).unwrap();
    graph["nodes"][0]["display_name"] = json!("CANARY-EDIT");
    let edited = root.join("edited.json");
    fs::write(&edited, serde_json::to_vec(&graph).unwrap()).unwrap();
    refused(&edited, &seeds, &[], Some("CANARY-EDIT"));
    // No entry point to seed from.
    refused(&graph_of(root, "mcp"), &seeds, &[], None);
    // An unsafe output directory.
    let result = run(&[
        "validate",
        "blast-radius",
        "--graph",
        real.to_str().unwrap(),
        "--seed-entry-points",
        "--output-dir",
        "a/../../escape",
    ]);
    assert_eq!(result.status.code(), Some(3));
}

#[test]
fn refusal_corpus_scenarios_and_bounds() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let graph_path = graph_of(root, "identity");
    let graph = read_graph(&graph_path);
    let base = |seeds: Value| json!({"schema_version": "1", "scenario_id": "s", "graph_id": graph.id, "seeds": seeds});
    let cases = [
        // Schema: an unknown field, and no seed.
        (
            json!({"schema_version": "1", "scenario_id": "s", "graph_id": graph.id,
                   "seeds": [{"node_id": USER_7, "kind": "PRINCIPAL_TAKEOVER"}],
                   "CANARY-KEY": 1}),
            Some("CANARY-KEY"),
        ),
        (base(json!([])), None),
        // Another graph.
        (
            json!({"schema_version": "1", "scenario_id": "s",
                   "graph_id": format!("graph:{}", "0".repeat(64)),
                   "seeds": [{"node_id": USER_7, "kind": "PRINCIPAL_TAKEOVER"}]}),
            None,
        ),
        // Unknown node and unknown entity.
        (
            base(json!([{"node_id": "node:human:CANARY-NODE", "kind": "PRINCIPAL_TAKEOVER"}])),
            Some("CANARY-NODE"),
        ),
        (
            base(json!([{"entity_id": "CANARY-ENTITY", "kind": "PRINCIPAL_TAKEOVER"}])),
            Some("CANARY-ENTITY"),
        ),
        // A kind that does not fit the node, and the same seed twice.
        (
            base(json!([{"node_id": USER_7, "kind": "CONTENT_INJECTION"}])),
            None,
        ),
        (
            base(json!([{"node_id": USER_7, "kind": "PRINCIPAL_TAKEOVER"},
                        {"node_id": USER_7, "kind": "PRINCIPAL_TAKEOVER"}])),
            None,
        ),
        // A scenario bound above its maximum.
        (
            json!({"schema_version": "1", "scenario_id": "s", "graph_id": graph.id,
                   "seeds": [{"node_id": USER_7, "kind": "PRINCIPAL_TAKEOVER"}],
                   "max_depth": 13}),
            None,
        ),
    ];
    for (i, (value, canary)) in cases.into_iter().enumerate() {
        let path = scenario(root, &format!("s{i}.json"), value);
        refused(
            &graph_path,
            &["--compromise", path.to_str().unwrap()],
            &[],
            canary,
        );
    }
    // An entity that names two nodes.
    let mut twice = graph.clone();
    let mut copy = twice
        .nodes
        .iter()
        .find(|n| n.id == "node:human:identity:569fbf2d8b1f:user-9")
        .unwrap()
        .clone();
    copy.id = "node:agent:shared".into();
    copy.node_type = dare_attack_graph::NodeType::Agent;
    twice.nodes.push(copy.clone());
    copy.id = "node:human:shared".into();
    copy.node_type = dare_attack_graph::NodeType::Human;
    twice.nodes.push(copy);
    let twice_path = root.join("twice.json");
    write_graph(&twice_path, twice);
    let twice_id = read_graph(&twice_path).id;
    let ambiguous = scenario(
        root,
        "ambiguous.json",
        json!({"schema_version": "1", "scenario_id": "s", "graph_id": twice_id,
               "seeds": [{"entity_id": "shared", "kind": "PRINCIPAL_TAKEOVER"}]}),
    );
    refused(
        &twice_path,
        &["--compromise", ambiguous.to_str().unwrap()],
        &[],
        None,
    );
    // Flags: above the maximum, and zero.
    let seeds = ["--seed-entry-points"];
    refused(&graph_path, &seeds, &["--max-depth", "13"], None);
    refused(&graph_path, &seeds, &["--max-states", "1000001"], None);
    refused(&graph_path, &seeds, &["--max-depth", "0"], None);
}

/// A credential-shaped id would leave through every output file: nothing is
/// written, and the value is not echoed.
#[test]
fn a_credential_shaped_value_is_never_written() {
    let root = tempfile::tempdir().unwrap();
    let path = graph_of(root.path(), "identity");
    let mut graph = read_graph(&path);
    let leaked = "node:resource:ghp_CANARYTOKEN0000000000";
    let mut copy = graph
        .nodes
        .iter()
        .find(|n| n.id.ends_with("document-123"))
        .unwrap()
        .clone();
    copy.id = leaked.into();
    graph.nodes.push(copy);
    let mut edge = graph
        .edges
        .iter()
        .find(|e| e.edge_type == dare_attack_graph::EdgeType::DelegatesTo)
        .unwrap()
        .clone();
    edge.edge_type = dare_attack_graph::EdgeType::Reads;
    edge.target = leaked.into();
    edge.id = dare_attack_graph::build_edge_id(
        &edge.source,
        edge.edge_type,
        &edge.target,
        &edge.authority,
    )
    .unwrap();
    graph.edges.push(edge);
    graph
        .targets
        .push(dare_attack_graph::v2::TargetDesignation {
            node: leaked.into(),
            class: dare_attack_graph::v2::TargetClass::SensitiveResource,
            origin: dare_attack_graph::v2::DesignationOrigin::Default,
        });
    graph.targets.sort();
    let doctored = root.path().join("leak.json");
    write_graph(&doctored, graph);
    refused(&doctored, &["--seed-entry-points"], &[], Some("ghp_"));
    let result = blast(
        &doctored,
        &["--seed-entry-points"],
        &[],
        &root.path().join("never"),
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("credential-shaped value"), "{stderr}");
}

#[test]
fn hostile_display_names_are_escaped_in_the_views() {
    let root = tempfile::tempdir().unwrap();
    let path = graph_of(root.path(), "identity");
    let mut graph = read_graph(&path);
    for node in &mut graph.nodes {
        if node.id == USER_7 {
            node.display_name = "\"]; click n0 call x() <script>".into();
        }
    }
    let hostile = root.path().join("hostile.json");
    write_graph(&hostile, graph);
    let out = root.path().join("out");
    let result = blast(&hostile, &["--seed-entry-points"], &[], &out);
    assert_eq!(result.status.code(), Some(2));
    let mermaid = fs::read_to_string(out.join("graph.mmd")).unwrap();
    let dot = fs::read_to_string(out.join("graph.dot")).unwrap();
    for view in [&mermaid, &dot] {
        assert!(
            view.contains("\\\"]; click n0 call x() &lt;script&gt;"),
            "{view}"
        );
        assert!(!view.contains("<script>"));
    }
}
