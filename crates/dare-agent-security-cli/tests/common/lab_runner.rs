//! The ATTACK-PATH-LAB runner, shared by `attack_path_lab.rs`,
//! `attack_path_goldens.rs` and `blast_radius_lab.rs` (Cycle 024 task-002).
//! Every engine and `validate attack-paths` run goes through the real binary.
#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use dare_attack_path::RunTag;
use serde_json::Value;

pub fn apl_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/attack-path-lab")
}

/// The APL-NNN scenario directories, sorted.
pub fn apl_scenarios() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(apl_root())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs
}

pub fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dare-agent-security"))
}

pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap())
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// The engine's own shipped scenario file for a built-in id: the bundle
/// binding re-checks it against the result's scenario digest.
pub fn shipped_scenario(engine: &str, id: &str) -> Option<PathBuf> {
    let lower = id.to_ascii_lowercase();
    let path = match engine {
        "tool-security" => repo().join(format!("fixtures/tool-security/scenarios/{id}.json")),
        "identity-security" | "memory-security" | "rag-security" | "mcp-auth-security" => repo()
            .join(format!(
                "crates/dare-{engine}/tests/fixtures/scenarios/{lower}.json"
            )),
        _ => return None,
    };
    Some(path)
}

/// Runs one engine and stages its inputs; returns the artifact directory.
pub fn run_engine(scenario_dir: &Path, run: &Value, out: &Path) -> PathBuf {
    let engine = run["engine"].as_str().unwrap();
    let mut args: Vec<String> = vec!["validate".into(), engine.into()];
    let remote = repo().join("crates/dare-agent-security-cli/tests/fixtures/remote-replay");
    match engine {
        "replay-capture" => {
            for (flag, file) in [
                ("--capture", "capture.json"),
                ("--audit", "audit.json"),
                ("--authorization", "authorization.json"),
                ("--plan", "plan.json"),
            ] {
                args.push(flag.into());
                args.push(remote.join(file).to_str().unwrap().into());
            }
        }
        _ => {
            args.push("--scenario".into());
            match (run["scenario"].as_str(), run["scenario_file"].as_str()) {
                (Some(id), None) => args.push(id.into()),
                (None, Some(file)) => args.push(scenario_dir.join(file).to_str().unwrap().into()),
                _ => panic!("{engine}: exactly one of scenario / scenario_file"),
            }
            if let Some(mode) = run["mode"].as_str() {
                args.push("--mode".into());
                args.push(mode.into());
            }
            if let Some(evidence) = run["evidence_dir"].as_str() {
                args.push("--evidence-dir".into());
                args.push(scenario_dir.join(evidence).to_str().unwrap().into());
            }
        }
    }
    args.push("--output-dir".into());
    args.push(out.to_str().unwrap().into());
    // Built-in scenario ids resolve against the repository root, as in CI.
    let output = Command::new(bin())
        .current_dir(repo())
        .args(&args)
        .output()
        .unwrap();
    let code = output.status.code();
    assert!(
        matches!(code, Some(0) | Some(2)),
        "{} {engine}: exit {code:?}\n{}",
        scenario_dir.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let inputs = out.join("inputs");
    if let Some(id) = run["scenario"].as_str() {
        if let Some(file) = shipped_scenario(engine, id) {
            fs::create_dir_all(&inputs).unwrap();
            fs::copy(&file, inputs.join("scenario.json"))
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
    if let Some(file) = run["scenario_file"].as_str() {
        fs::create_dir_all(&inputs).unwrap();
        fs::copy(scenario_dir.join(file), inputs.join("scenario.json")).unwrap();
    }
    if let Some(evidence) = run["evidence_dir"].as_str() {
        copy_dir(&scenario_dir.join(evidence), &inputs.join("evidence"));
    }
    out.to_path_buf()
}

pub fn result_file(dir: &Path) -> PathBuf {
    let found: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with("-result.json"))
        })
        .collect();
    assert_eq!(found.len(), 1, "{}: one result file", dir.display());
    found.into_iter().next().unwrap()
}

pub fn substitute(text: &str, tags: &[String]) -> String {
    let mut out = text.to_owned();
    for (index, tag) in tags.iter().enumerate() {
        out = out.replace(&format!("${{run:{index}}}"), tag);
    }
    assert!(!out.contains("${run:"), "unknown run placeholder");
    out
}

pub struct Outcome {
    pub exit: i32,
    pub files: BTreeMap<String, Vec<u8>>,
}

pub fn attack_paths(artifacts: &[PathBuf], model: Option<&Path>, out: &Path) -> Outcome {
    let mut args: Vec<String> = vec!["validate".into(), "attack-paths".into()];
    for dir in artifacts {
        args.push("--artifacts".into());
        args.push(dir.to_str().unwrap().into());
    }
    if let Some(model) = model {
        args.push("--system-model".into());
        args.push(model.to_str().unwrap().into());
    }
    args.push("--output-dir".into());
    args.push(out.to_str().unwrap().into());
    let output = Command::new(bin()).args(&args).output().unwrap();
    let exit = output.status.code().unwrap_or(-1);
    assert!(
        exit == 0 || exit == 2,
        "attack-paths exit {exit}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(out).unwrap() {
        let entry = entry.unwrap();
        files.insert(
            entry.file_name().into_string().unwrap(),
            fs::read(entry.path()).unwrap(),
        );
    }
    Outcome { exit, files }
}

pub fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// One ATTACK-PATH-LAB scenario's engine runs and rendered system model,
/// ready for `validate attack-paths`.
pub struct Built {
    pub name: String,
    pub lab: Value,
    pub artifacts: Vec<PathBuf>,
    pub tags: Vec<String>,
    pub model: Option<PathBuf>,
}

/// Runs every engine of `dir/lab.json` through the real binary into `tmp`,
/// stages the inputs, and renders `system-model.json` with the run tags.
/// Refuses anything that looks like a hand-written graph input (O-01).
pub fn build_apl(dir: &Path, tmp: &Path) -> Built {
    let name = dir.file_name().unwrap().to_str().unwrap().to_owned();
    let lab = read_json(&dir.join("lab.json"));
    assert_eq!(lab["id"], name.as_str(), "lab.json id");
    // O-01: no graph facts by hand. The directory holds engine scenarios,
    // engine evidence documents, the system model and the expectation only.
    for entry in walk(dir) {
        let file = entry.file_name().unwrap().to_str().unwrap().to_owned();
        assert!(
            !file.contains("facts") && !file.contains("attack-graph") && !file.contains("paths"),
            "{name}: {file} looks like a hand-written graph input"
        );
    }
    let mut artifacts = Vec::new();
    let mut tags = Vec::new();
    for (index, run) in lab["runs"].as_array().unwrap().iter().enumerate() {
        let out = run_engine(dir, run, &tmp.join(format!("run-{index}")));
        tags.push(
            RunTag::from_result_bytes(&fs::read(result_file(&out)).unwrap())
                .as_str()
                .to_owned(),
        );
        artifacts.push(out);
    }
    let model = dir.join("system-model.json");
    let model = model.exists().then(|| {
        let rendered = tmp.join("system-model.json");
        let text = substitute(&fs::read_to_string(&model).unwrap(), &tags);
        let value: Value = serde_json::from_str(&text).unwrap();
        if lab["declared_edges"].as_bool() != Some(true) {
            assert!(
                value.get("declared_edges").is_none(),
                "{name}: declared edges are allowed only where lab.json says why"
            );
        }
        fs::write(&rendered, text).unwrap();
        rendered
    });
    Built {
        name,
        lab,
        artifacts,
        tags,
        model,
    }
}
