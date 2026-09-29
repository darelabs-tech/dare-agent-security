//! ATTACK-PATH-LAB (BLUEPRINT §8.1, tasks 039 and 040).
//!
//! Every scenario under `tests/fixtures/attack-path-lab/APL-NNN/` is run end
//! to end through the real binary:
//!
//! 1. each engine run listed in `lab.json` is executed with
//!    `validate <engine> … --output-dir <tmp>/run-<i>`;
//! 2. the engine inputs are copied into `<tmp>/run-<i>/inputs/`;
//! 3. `validate attack-paths` runs over those directories, twice, the second
//!    time with the artifacts in reverse order, and the two outputs must be
//!    byte-identical;
//! 4. `attack-paths.json` is compared with `expected.json`.
//!
//! No graph fact is written by hand: the only inputs are engine scenarios,
//! engine evidence documents and a system model. `${run:N}` in the model and in
//! `expected.json` is replaced by the run tag of run N, the first 12 hex digits
//! of the SHA-256 of that run's result file, so a node no alias names can still
//! be referred to.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use serde_json::Value;

mod common;
use common::lab_runner::*;

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|a| a.iter().map(|v| v.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default()
}

fn failed_properties(path: &Value) -> Vec<String> {
    let set: BTreeSet<String> = path["failed_guards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["property"].as_str().unwrap().to_owned())
        .collect();
    set.into_iter().collect()
}

fn describe(doc: &Value) -> String {
    let mut out = String::new();
    for (key, list) in [("path", "paths"), ("discontinuous", "discontinuous_paths")] {
        for path in doc[list].as_array().unwrap() {
            out.push_str(&format!(
                "  {key} {} {} {} -> {} {:?} at={}\n",
                path["control_state"].as_str().unwrap(),
                path["entry_class"].as_str().unwrap(),
                path["target_class"].as_str().unwrap(),
                strings(&path["nodes"]).join(" > "),
                failed_properties(path),
                path["discontinuity_at"],
            ));
        }
    }
    out
}

/// Checks one scenario; returns its lab description for the class contract.
fn check(dir: &Path) -> Value {
    let tmp = tempfile::tempdir().unwrap();
    let Built {
        name,
        lab,
        artifacts,
        tags,
        model,
    } = build_apl(dir, tmp.path());
    let first = attack_paths(&artifacts, model.as_deref(), &tmp.path().join("ap-1"));
    let mut reversed = artifacts.clone();
    reversed.reverse();
    let second = attack_paths(&reversed, model.as_deref(), &tmp.path().join("ap-2"));
    assert_eq!(first.exit, second.exit, "{name}: exit differs across runs");
    assert_eq!(
        first.files.keys().collect::<Vec<_>>(),
        second.files.keys().collect::<Vec<_>>()
    );
    for (file, bytes) in &first.files {
        assert!(
            *bytes == second.files[file],
            "{name}: {file} differs when the artifacts are given in another order"
        );
    }
    if let Ok(keep) = std::env::var("APL_KEEP") {
        copy_dir(tmp.path(), &Path::new(&keep).join(&name));
    }
    let doc: Value = serde_json::from_slice(&first.files["attack-paths.json"]).unwrap();
    let graph: Value = serde_json::from_slice(&first.files["attack-graph.json"]).unwrap();
    let report: Value = serde_json::from_slice(&first.files["projection-report.json"]).unwrap();
    let expected: Value = serde_json::from_str(&substitute(
        &fs::read_to_string(dir.join("expected.json")).unwrap(),
        &tags,
    ))
    .unwrap();
    let actual = describe(&doc);
    let context = format!("{name}\nactual:\n{actual}");

    assert_eq!(
        first.exit,
        expected["exit"].as_i64().unwrap() as i32,
        "{context}"
    );
    let feasible = doc["paths"].as_array().unwrap();
    let discontinuous = doc["discontinuous_paths"].as_array().unwrap();
    let find = |list: &[Value], nodes: &[String]| -> Option<Value> {
        list.iter().find(|p| strings(&p["nodes"]) == nodes).cloned()
    };
    for want in expected["paths"].as_array().into_iter().flatten() {
        let nodes = strings(&want["nodes"]);
        // The same nodes can reach a target under two classes, or over two
        // parallel edges; the expectation names the class when it matters.
        let got = feasible
            .iter()
            .find(|p| {
                strings(&p["nodes"]) == nodes
                    && want
                        .get("target_class")
                        .is_none_or(|class| &p["target_class"] == class)
            })
            .cloned()
            .unwrap_or_else(|| panic!("missing path {nodes:?}\n{context}"));
        for key in ["control_state", "entry_class", "target_class", "status"] {
            if let Some(value) = want.get(key) {
                assert_eq!(&got[key], value, "{key} of {nodes:?}\n{context}");
            }
        }
        let wanted: Vec<String> = strings(&want["failed_properties"]);
        assert_eq!(
            failed_properties(&got),
            wanted,
            "failed properties of {nodes:?}\n{context}"
        );
    }
    for want in expected["discontinuous"].as_array().into_iter().flatten() {
        let nodes = strings(&want["nodes"]);
        let got = find(discontinuous, &nodes)
            .unwrap_or_else(|| panic!("missing discontinuous path {nodes:?}\n{context}"));
        assert_eq!(got["feasibility"], "DISCONTINUOUS", "{context}");
        assert_eq!(got["discontinuity_at"], want["at"], "{context}");
        assert!(find(feasible, &nodes).is_none(), "{context}");
    }
    for absent in expected["absent"].as_array().into_iter().flatten() {
        let nodes = strings(absent);
        assert!(
            find(feasible, &nodes).is_none() && find(discontinuous, &nodes).is_none(),
            "path {nodes:?} must be absent\n{context}"
        );
    }
    for property in strings(&expected["no_failed_property"]) {
        assert!(
            feasible
                .iter()
                .all(|p| !failed_properties(p).contains(&property)),
            "no feasible path may fail on {property}\n{context}"
        );
    }
    // Discontinuous paths never gate and never make a chokepoint.
    for choke in doc["chokepoints"].as_array().unwrap() {
        let edge = choke["edge"].as_str().unwrap();
        assert!(
            feasible
                .iter()
                .any(|p| strings(&p["edges"]).iter().any(|e| e == edge)),
            "{context}"
        );
    }
    for want in expected["chokepoints"].as_array().into_iter().flatten() {
        let target = want["target"].as_str().unwrap();
        let properties = strings(&want["properties"]);
        assert!(
            doc["chokepoints"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["target"] == target && strings(&c["properties"]) == properties),
            "chokepoint {target} {properties:?}\n{context}\n{}",
            doc["chokepoints"]
        );
    }
    if let Some(nodes) = expected["node_ids"].as_array() {
        let ids: BTreeSet<String> = graph["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["id"].as_str().unwrap().to_owned())
            .collect();
        for id in nodes {
            assert!(ids.contains(id.as_str().unwrap()), "node {id}\n{context}");
        }
    }
    if let Some(sources) = expected.get("artifacts") {
        let artifacts = graph["sources"]["artifacts"].as_array().unwrap();
        let dynamic = artifacts
            .iter()
            .filter(|a| a["dynamic_authorized"] == true)
            .count();
        assert_eq!(
            dynamic as u64,
            sources["dynamic_authorized"].as_u64().unwrap(),
            "{context}"
        );
        for (kind, count) in sources["unprojected"].as_object().into_iter().flatten() {
            let total: u64 = report["artifacts"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|a| a["unprojected"][kind.as_str()].as_u64())
                .sum();
            assert_eq!(
                total,
                count.as_u64().unwrap(),
                "unprojected {kind}\n{context}"
            );
        }
    }
    if let Some(summary) = expected["summary_contains"].as_array() {
        let text = String::from_utf8_lossy(&first.files["summary.md"]).into_owned();
        for needle in summary {
            assert!(
                text.contains(needle.as_str().unwrap()),
                "summary: {needle}\n{text}"
            );
        }
    }
    let mut lab = lab;
    lab["expected"] = expected;
    lab
}

/// Every scenario runs; then the class contract (BLUEPRINT §8.1) holds over
/// the whole set:
/// - every chain class has an attack scenario and at least one control twin;
/// - every `CONTROL_FAILED` expectation names the failing property;
/// - the control twin of a class fails on none of the properties its attack
///   scenarios fail on.
#[test]
fn attack_path_lab() {
    let only = std::env::var("APL_ONLY").ok();
    let mut labs = Vec::new();
    for dir in apl_scenarios() {
        let name = dir.file_name().unwrap().to_str().unwrap();
        if only.as_deref().is_some_and(|o| o != name) {
            continue;
        }
        labs.push(check(&dir));
    }
    if only.is_some() {
        return;
    }
    let ids: Vec<&str> = labs.iter().map(|l| l["id"].as_str().unwrap()).collect();
    let want: Vec<String> = (1..=26).map(|n| format!("APL-{n:03}")).collect();
    assert_eq!(ids, want, "the lab holds APL-001..APL-026");

    let mut classes: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for lab in &labs {
        classes
            .entry(lab["class"].as_str().unwrap().to_owned())
            .or_default()
            .push(lab);
        for path in lab["expected"]["paths"].as_array().into_iter().flatten() {
            if path["control_state"] == "CONTROL_FAILED" {
                assert!(
                    !strings(&path["failed_properties"]).is_empty(),
                    "{}: a CONTROL_FAILED expectation names its property",
                    lab["id"]
                );
            }
        }
    }
    for (class, members) in &classes {
        let role = |r: &'static str| members.iter().filter(move |l| l["role"] == r);
        if role("structural").count() == members.len() {
            continue;
        }
        assert!(
            role("attack").count() > 0,
            "class {class}: an attack scenario"
        );
        assert!(role("control").count() > 0, "class {class}: a control twin");
        let attacked: BTreeSet<String> = role("attack")
            .flat_map(|l| l["expected"]["paths"].as_array().unwrap().iter())
            .flat_map(|p| strings(&p["failed_properties"]))
            .collect();
        assert!(
            !attacked.is_empty(),
            "class {class}: the attack fails a control"
        );
        for twin in role("control") {
            let guarded: BTreeSet<String> = strings(&twin["expected"]["no_failed_property"])
                .into_iter()
                .collect();
            let unguarded: Vec<&String> = attacked.difference(&guarded).collect();
            assert!(
                unguarded.is_empty(),
                "class {class}: control twin {} must assert that {unguarded:?} no longer fail",
                twin["id"]
            );
        }
    }
}
