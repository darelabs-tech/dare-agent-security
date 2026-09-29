//! Cycle 024 task-002 (O-07): `validate attack-paths` keeps producing the same
//! bytes for every ATTACK-PATH-LAB scenario. The continuity rule and the
//! output sweep move into `dare-attack-graph` in this cycle; these digests
//! prove that the move changed no byte of Cycle 023 output.
//!
//! The engines stamp their evidence with the wall clock, and some results
//! carry run-specific values, so re-running an engine gives different artifact
//! bytes. The goldens therefore run over a **frozen snapshot** of each unique
//! engine run the lab uses (`tests/fixtures/attack-path-lab-frozen/`), taken
//! at the Cycle 024 baseline by `regenerate_frozen_runs_and_goldens`. Only
//! what `validate attack-paths` reads is kept: the result, the evidence, the
//! multi-turn transcript and `inputs/`.
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use dare_attack_path::{ids::sha256_prefixed, RunTag};
use serde_json::Value;

mod common;
use common::lab_runner::*;

fn frozen_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/attack-path-lab-frozen")
}

fn goldens_file() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/attack-path-lab-goldens.txt")
}

/// A stable directory name for one engine run of a lab scenario.
fn run_key(scenario: &str, run: &Value) -> String {
    let engine = run["engine"].as_str().unwrap();
    match (run["scenario"].as_str(), run["scenario_file"].as_str()) {
        (Some(id), _) => format!("{engine}__{id}"),
        (None, Some(_)) => format!("{engine}__{scenario}"),
        (None, None) => engine.to_owned(),
    }
}

fn keep(name: &str) -> bool {
    name.ends_with("-result.json")
        || name.ends_with("-evidence.json")
        || name == "multi-turn-conversations.json"
}

fn freeze(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if entry.file_type().unwrap().is_dir() {
            if name == "inputs" {
                copy_dir(&entry.path(), &to.join("inputs"));
            }
        } else if keep(&name) {
            fs::copy(entry.path(), to.join(&name)).unwrap();
        }
    }
}

/// `validate attack-paths` over the frozen runs of one scenario.
fn run_frozen(dir: &Path, tmp: &Path) -> (String, Outcome) {
    let name = dir.file_name().unwrap().to_str().unwrap().to_owned();
    let lab = read_json(&dir.join("lab.json"));
    let mut artifacts = Vec::new();
    let mut tags = Vec::new();
    for run in lab["runs"].as_array().unwrap() {
        let frozen = frozen_root().join(run_key(&name, run));
        tags.push(
            RunTag::from_result_bytes(&fs::read(result_file(&frozen)).unwrap())
                .as_str()
                .to_owned(),
        );
        artifacts.push(frozen);
    }
    let model = dir.join("system-model.json");
    let model = model.exists().then(|| {
        let rendered = tmp.join("system-model.json");
        fs::write(
            &rendered,
            substitute(&fs::read_to_string(&model).unwrap(), &tags),
        )
        .unwrap();
        rendered
    });
    (
        name,
        attack_paths(&artifacts, model.as_deref(), &tmp.join("ap")),
    )
}

fn digest(bytes: &[u8]) -> String {
    sha256_prefixed(bytes)[7..].to_owned()
}

fn read_goldens() -> BTreeMap<(String, String), String> {
    fs::read_to_string(goldens_file())
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            assert_eq!(parts.len(), 3, "{l}");
            (
                (parts[0].to_owned(), parts[1].to_owned()),
                parts[2].to_owned(),
            )
        })
        .collect()
}

#[test]
fn every_attack_path_lab_output_keeps_its_baseline_digest() {
    let goldens = read_goldens();
    assert_eq!(goldens.len(), 26 * 6, "26 scenarios × 6 files");
    let mut checked = 0;
    for dir in apl_scenarios() {
        let tmp = tempfile::tempdir().unwrap();
        let (name, out) = run_frozen(&dir, tmp.path());
        assert_eq!(out.files.len(), 6, "{name}");
        let graph: Value = serde_json::from_slice(&out.files["attack-graph.json"]).unwrap();
        // The digests assume the default build: no DARE_BUILD_COMMIT.
        assert_eq!(graph["engine"]["commit"], "unrecorded", "{name}");
        for (file, bytes) in &out.files {
            let want = goldens
                .get(&(name.clone(), file.clone()))
                .unwrap_or_else(|| panic!("no golden for {name} {file}"));
            assert_eq!(&digest(bytes), want, "{name} {file} changed");
            checked += 1;
        }
    }
    assert_eq!(checked, 156);
}

/// Every run the lab names has a frozen copy, and every frozen copy is used.
#[test]
fn the_frozen_runs_match_the_lab() {
    let mut wanted = std::collections::BTreeSet::new();
    for dir in apl_scenarios() {
        let name = dir.file_name().unwrap().to_str().unwrap().to_owned();
        let lab = read_json(&dir.join("lab.json"));
        for run in lab["runs"].as_array().unwrap() {
            wanted.insert(run_key(&name, run));
        }
    }
    let present: std::collections::BTreeSet<String> = fs::read_dir(frozen_root())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(wanted, present);
}

/// Freezes one fresh run of every engine run the lab uses, then records the
/// goldens over them. Run only at a baseline, with the tree whose output is to
/// be pinned: `cargo test -p dare-agent-security --test attack_path_goldens
/// -- --ignored`.
#[test]
#[ignore = "writes the frozen runs and the goldens; run only at a baseline"]
fn regenerate_frozen_runs_and_goldens() {
    let root = frozen_root();
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    for dir in apl_scenarios() {
        let tmp = tempfile::tempdir().unwrap();
        let built = build_apl(&dir, tmp.path());
        for (run, artifact) in built.lab["runs"]
            .as_array()
            .unwrap()
            .iter()
            .zip(&built.artifacts)
        {
            let target = root.join(run_key(&built.name, run));
            if !target.exists() {
                freeze(artifact, &target);
            }
        }
    }
    let mut lines = vec![
        "# SHA-256 of every `validate attack-paths` output file for every ATTACK-PATH-LAB"
            .to_owned(),
        "# scenario, over tests/fixtures/attack-path-lab-frozen/ (Cycle 024 task-002).".to_owned(),
        "# <scenario> <file> <sha256>".to_owned(),
    ];
    for dir in apl_scenarios() {
        let tmp = tempfile::tempdir().unwrap();
        let (name, out) = run_frozen(&dir, tmp.path());
        for (file, bytes) in &out.files {
            lines.push(format!("{name} {file} {}", digest(bytes)));
        }
    }
    lines.push(String::new());
    fs::write(goldens_file(), lines.join("\n")).unwrap();
}
