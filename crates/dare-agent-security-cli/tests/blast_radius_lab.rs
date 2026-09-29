//! BLAST-RADIUS-LAB (Cycle 024 BLUEPRINT §7.1, tasks 023 and 024).
//!
//! Every scenario under `tests/fixtures/blast-radius-lab/BRL-NNN/` runs end to
//! end through the real binary:
//!
//! 1. the ATTACK-PATH-LAB scenario `lab.json` names in `graph_from` is built
//!    with the shared runner: its engines run, its system model is rendered,
//!    and `validate attack-paths` writes the graph;
//! 2. `compromise.json` is rendered, `${graph_id}` and `${run:N}` substituted;
//! 3. `validate blast-radius` runs twice, and the two outputs must be
//!    byte-identical;
//! 4. the document passes `validate_blast_radius` and is compared with
//!    `expected.json`.
//!
//! No graph is written by hand: the only inputs are the APL scenario, a
//! compromise scenario and the expectation.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use dare_attack_graph::v2::AttackGraphV2;
use dare_blast_radius::{model::BlastRadiusDoc, validate_blast_radius};
use serde_json::Value;

mod common;
use common::lab_runner::*;

const FILES: [&str; 4] = ["blast-radius.json", "graph.dot", "graph.mmd", "summary.md"];

fn brl_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/blast-radius-lab")
}

fn brl_scenarios() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(brl_root())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|a| a.iter().map(|v| v.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default()
}

/// An APL scenario built once: its graph file, graph and run tags.
struct Graph {
    path: PathBuf,
    graph: AttackGraphV2,
    tags: Vec<String>,
}

fn build_graph(apl: &str, tmp: &Path) -> Graph {
    let built = build_apl(&apl_root().join(apl), &tmp.join("runs"));
    let out = tmp.join("attack-paths");
    let outcome = attack_paths(&built.artifacts, built.model.as_deref(), &out);
    assert!(outcome.files.contains_key("attack-graph.json"), "{apl}");
    let path = out.join("attack-graph.json");
    let graph = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    Graph {
        path,
        graph,
        tags: built.tags,
    }
}

fn render(text: &str, graph: &Graph) -> String {
    substitute(&text.replace("${graph_id}", &graph.graph.id), &graph.tags)
}

struct Run {
    exit: i32,
    files: BTreeMap<String, Vec<u8>>,
    stderr: String,
}

fn blast_radius(graph: &Graph, lab: &Value, compromise: Option<&Path>, out: &Path) -> Run {
    let mut args: Vec<String> = vec![
        "validate".into(),
        "blast-radius".into(),
        "--graph".into(),
        graph.path.to_str().unwrap().into(),
        "--output-dir".into(),
        out.to_str().unwrap().into(),
    ];
    match compromise {
        Some(path) => {
            args.push("--compromise".into());
            args.push(path.to_str().unwrap().into());
        }
        None => args.push("--seed-entry-points".into()),
    }
    args.extend(strings(&lab["flags"]));
    let output = Command::new(bin()).args(&args).output().unwrap();
    let mut files = BTreeMap::new();
    if out.exists() {
        for entry in fs::read_dir(out).unwrap() {
            let entry = entry.unwrap();
            files.insert(
                entry.file_name().into_string().unwrap(),
                fs::read(entry.path()).unwrap(),
            );
        }
    }
    Run {
        exit: output.status.code().unwrap_or(-1),
        files,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn describe(doc: &BlastRadiusDoc) -> String {
    let mut out = String::new();
    for seed in &doc.seeds {
        out.push_str(&format!(
            "  seed {} {:?} refused={} truncated={}\n",
            seed.node,
            seed.kind,
            seed.structural.refused_steps,
            seed.structural.truncated || seed.uncontained.truncated
        ));
        for t in &seed.targets {
            let route = t.uncontained_route.as_ref().unwrap_or(&t.structural_route);
            let failed: BTreeSet<&str> = route
                .failed_guards
                .iter()
                .map(|g| g.property.as_str())
                .collect();
            out.push_str(&format!(
                "    {:?} {:?} {} via {} {:?} {:?} frontier={:?}\n",
                t.exposure,
                t.class,
                t.node,
                route.nodes.join(" > "),
                route.control_state,
                failed,
                t.frontier
            ));
        }
    }
    for d in &doc.remediation_delta {
        out.push_str(&format!(
            "  delta {} {:?} {} partial={}\n",
            d.edge, d.properties, d.targets_contained_if_held, d.partial
        ));
    }
    out
}

fn frontier_properties(graph: &AttackGraphV2, edges: &[String]) -> Vec<String> {
    let set: BTreeSet<String> = edges
        .iter()
        .filter_map(|id| graph.edges.iter().find(|e| &e.id == id))
        .flat_map(|e| e.guards.iter().map(|g| g.property.clone()))
        .collect();
    set.into_iter().collect()
}

/// Compares the document with `expected.json`; returns every mismatch.
fn compare(name: &str, graph: &Graph, doc: &BlastRadiusDoc, expected: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let mut check = |ok: bool, what: String| {
        if !ok {
            problems.push(format!("{name}: {what}"));
        }
    };
    check(
        doc.truncated == expected["truncated"].as_bool().unwrap_or(false),
        format!("truncated is {}", doc.truncated),
    );
    for want in expected["seeds"].as_array().unwrap() {
        let node = render(want["node"].as_str().unwrap(), graph);
        let Some(seed) = doc.seeds.iter().find(|s| s.node == node) else {
            check(false, format!("no seed {node}"));
            continue;
        };
        if let Some(kind) = want["kind"].as_str() {
            check(
                serde_json::to_value(seed.kind).unwrap() == kind,
                format!("{node} kind {:?}", seed.kind),
            );
        }
        if let Some(min) = want["refused_steps_min"].as_u64() {
            check(
                seed.structural.refused_steps >= min,
                format!("{node} refused_steps {}", seed.structural.refused_steps),
            );
        }
        for absent in strings(&want["absent"]) {
            let absent = render(&absent, graph);
            check(
                !seed.targets.iter().any(|t| t.node == absent),
                format!("{node}: {absent} should be absent"),
            );
        }
        for target in want["targets"].as_array().unwrap() {
            let id = render(target["node"].as_str().unwrap(), graph);
            let Some(t) = seed.targets.iter().find(|t| t.node == id) else {
                check(false, format!("{node}: no target {id}"));
                continue;
            };
            let exposure = target["exposure"].as_str().unwrap();
            check(
                serde_json::to_value(t.exposure).unwrap() == exposure,
                format!("{id}: exposure {:?}", t.exposure),
            );
            if let Some(class) = target["class"].as_str() {
                check(
                    serde_json::to_value(t.class).unwrap() == class,
                    format!("{id}: class {:?}", t.class),
                );
            }
            let route = t.uncontained_route.as_ref().unwrap_or(&t.structural_route);
            if let Some(nodes) = target.get("route") {
                let nodes: Vec<String> = strings(nodes).iter().map(|n| render(n, graph)).collect();
                check(
                    route.nodes == nodes,
                    format!("{id}: route {:?}", route.nodes),
                );
            }
            if let Some(state) = target["control_state"].as_str() {
                check(
                    serde_json::to_value(route.control_state).unwrap() == state,
                    format!("{id}: control {:?}", route.control_state),
                );
            }
            if let Some(failed) = target.get("failed_properties") {
                let got: BTreeSet<String> = route
                    .failed_guards
                    .iter()
                    .map(|g| g.property.clone())
                    .collect();
                check(
                    got.into_iter().collect::<Vec<_>>() == strings(failed),
                    format!("{id}: failed properties"),
                );
            }
            if let Some(frontier) = target.get("frontier_properties") {
                check(
                    frontier_properties(&graph.graph, &t.frontier) == strings(frontier),
                    format!("{id}: frontier {:?}", t.frontier),
                );
            }
        }
    }
    if let Some(delta) = expected["delta"].as_array() {
        for want in delta {
            let properties = strings(&want["properties"]);
            let count = want["targets_contained_if_held"].as_u64().unwrap();
            check(
                doc.remediation_delta.iter().any(|d| {
                    d.properties == properties && u64::from(d.targets_contained_if_held) == count
                }),
                format!("no delta {properties:?} = {count}"),
            );
        }
    }
    problems
}

fn check_scenario(dir: &Path, graphs: &mut BTreeMap<String, Graph>, root: &Path) -> Vec<String> {
    let name = dir.file_name().unwrap().to_str().unwrap().to_owned();
    let lab = read_json(&dir.join("lab.json"));
    assert_eq!(lab["id"], name.as_str(), "lab.json id");
    let apl = lab["graph_from"].as_str().unwrap().to_owned();
    let graph = graphs
        .entry(apl.clone())
        .or_insert_with(|| build_graph(&apl, &root.join(&apl)));
    let tmp = root.join(&name);
    fs::create_dir_all(&tmp).unwrap();
    let template = dir.join("compromise.json");
    let compromise = template.exists().then(|| {
        let path = tmp.join("compromise.json");
        fs::write(
            &path,
            render(&fs::read_to_string(&template).unwrap(), graph),
        )
        .unwrap();
        path
    });
    assert_eq!(
        compromise.is_none(),
        lab["seed_entry_points"].as_bool() == Some(true),
        "{name}: a compromise file or --seed-entry-points"
    );
    let first = blast_radius(graph, &lab, compromise.as_deref(), &tmp.join("a"));
    let second = blast_radius(graph, &lab, compromise.as_deref(), &tmp.join("b"));
    let expected = read_json(&dir.join("expected.json"));
    let mut problems = Vec::new();
    if first.exit != expected["exit"].as_i64().unwrap() as i32 {
        problems.push(format!("{name}: exit {} ({})", first.exit, first.stderr));
    }
    assert_eq!(first.files, second.files, "{name}: two runs differ");
    assert_eq!(
        first.files.keys().map(String::as_str).collect::<Vec<_>>(),
        FILES,
        "{name}: {}",
        first.stderr
    );
    let doc: BlastRadiusDoc = serde_json::from_slice(&first.files["blast-radius.json"]).unwrap();
    validate_blast_radius(&graph.graph, &doc).unwrap_or_else(|e| panic!("{name}: {e}"));
    let found = compare(&name, graph, &doc, &expected);
    if !found.is_empty() {
        problems.extend(found);
        problems.push(describe(&doc));
    }
    problems
}

#[test]
fn every_blast_radius_lab_scenario_matches_its_expectation() {
    let root = tempfile::tempdir().unwrap();
    let mut graphs = BTreeMap::new();
    let mut problems = Vec::new();
    let scenarios = brl_scenarios();
    assert_eq!(scenarios.len(), 20, "BRL-001..BRL-020");
    for dir in &scenarios {
        problems.extend(check_scenario(dir, &mut graphs, root.path()));
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

/// The class contract (§7.1): every attack class has a control twin; every
/// `EXPOSED` expectation with `CONTROL_FAILED` names its property; every
/// `CONTAINED` expectation names its frontier properties.
#[test]
fn the_lab_keeps_its_class_contract() {
    let mut roles: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for dir in brl_scenarios() {
        let lab = read_json(&dir.join("lab.json"));
        roles
            .entry(lab["class"].as_str().unwrap().to_owned())
            .or_default()
            .insert(lab["role"].as_str().unwrap().to_owned());
        let expected = read_json(&dir.join("expected.json"));
        for seed in expected["seeds"].as_array().unwrap() {
            for target in seed["targets"].as_array().unwrap() {
                match target["exposure"].as_str().unwrap() {
                    "EXPOSED" if target["control_state"] == "CONTROL_FAILED" => assert!(
                        !strings(&target["failed_properties"]).is_empty(),
                        "{}: EXPOSED without its property",
                        dir.display()
                    ),
                    "CONTAINED" => assert!(
                        !strings(&target["frontier_properties"]).is_empty(),
                        "{}: CONTAINED without its frontier",
                        dir.display()
                    ),
                    _ => {}
                }
            }
        }
    }
    for (class, roles) in &roles {
        if roles.contains("attack") {
            assert!(
                roles.contains("control"),
                "class {class} has no control twin"
            );
        }
    }
}

/// Writes every APL graph and its entry-point blast radius to a directory,
/// for writing expectations: `DARE_BRL_DUMP=<dir> cargo test -p
/// dare-agent-security --test blast_radius_lab -- --ignored dump`.
#[test]
#[ignore = "a tool for writing expectations"]
fn dump() {
    let Some(target) = std::env::var_os("DARE_BRL_DUMP") else {
        return;
    };
    let target = PathBuf::from(target);
    let root = tempfile::tempdir().unwrap();
    for dir in apl_scenarios() {
        let apl = dir.file_name().unwrap().to_str().unwrap().to_owned();
        let graph = build_graph(&apl, &root.path().join(&apl));
        let out = target.join(&apl);
        fs::create_dir_all(&out).unwrap();
        fs::copy(&graph.path, out.join("attack-graph.json")).unwrap();
        fs::write(out.join("tags.txt"), graph.tags.join("\n")).unwrap();
        let lab = serde_json::json!({});
        let run = blast_radius(&graph, &lab, None, &out.join("entry-points"));
        if let Some(bytes) = run.files.get("blast-radius.json") {
            let doc: BlastRadiusDoc = serde_json::from_slice(bytes).unwrap();
            fs::write(out.join("describe.txt"), describe(&doc)).unwrap();
        } else {
            fs::write(out.join("describe.txt"), &run.stderr).unwrap();
        }
    }
}
