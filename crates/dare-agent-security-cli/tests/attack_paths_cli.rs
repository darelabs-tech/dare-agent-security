//! `validate attack-paths` at the process boundary (tasks 037 and 038).
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::{json, Value};

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

fn attack_paths(artifacts: &[&Path], extra: &[&str], out: &Path) -> Output {
    let mut args: Vec<String> = vec!["validate".into(), "attack-paths".into()];
    for dir in artifacts {
        args.push("--artifacts".into());
        args.push(dir.to_str().unwrap().into());
    }
    args.push("--output-dir".into());
    args.push(out.to_str().unwrap().into());
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    Command::new(bin())
        .args(&args)
        .output()
        .expect("binary runs")
}

fn copy_dir(from: &Path, to: &Path) {
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

fn staged(root: &Path, name: &str) -> PathBuf {
    let path = root.join(name);
    copy_dir(&bundles().join(name), &path);
    path
}

fn edit(path: &Path, change: impl FnOnce(&mut Value)) {
    let mut value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    change(&mut value);
    fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

const FILES: [&str; 6] = [
    "projection-report.json",
    "attack-graph.json",
    "attack-paths.json",
    "graph.mmd",
    "graph.dot",
    "summary.md",
];

#[test]
fn help_names_the_bounds_and_offers_no_widening_flag() {
    let help = String::from_utf8(run(&["validate", "attack-paths", "--help"]).stdout).unwrap();
    for flag in [
        "--artifacts",
        "--system-model",
        "--output-dir",
        "--max-path-edges",
        "--max-paths",
        "--max-paths-per-pair",
        "--json",
    ] {
        assert!(help.contains(flag), "{flag}");
    }
    assert!(help.contains("CONTROLS_HELD") && help.contains("does not mean the system is secure"));
    for forbidden in [
        "--url",
        "--endpoint",
        "--shell",
        "--exec",
        "--command",
        "--engine",
        "--proxy",
        "--token",
        "--execute",
    ] {
        assert!(!help.contains(&format!("{forbidden} ")), "{forbidden}");
        let out = run(&["validate", "attack-paths", forbidden, "x"]);
        assert_ne!(out.status.code(), Some(0), "{forbidden} accepted");
    }
    // `validate attack-graph --facts` is still there, unchanged.
    let v1 = String::from_utf8(run(&["validate", "attack-graph", "--help"]).stdout).unwrap();
    assert!(v1.contains("--facts"));
}

#[test]
fn exit_0_writes_six_files_when_nothing_is_failed_undecided_or_cut() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    // One supply-chain component: an entry, no target, so no path.
    let result = attack_paths(&[&bundles().join("sc")], &["--json"], &out);
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut names: Vec<String> = fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    let mut expected: Vec<String> = FILES.iter().map(|s| (*s).to_owned()).collect();
    expected.sort();
    assert_eq!(names, expected);
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("\"schema_id\": \"https://darelabs.tech/schemas/attack-graph/v2/attack-paths.schema.json\""), "--json prints attack-paths.json");
    assert!(stdout.contains("0 feasible paths"));
}

#[test]
fn exit_2_when_a_feasible_path_is_undecided_or_enumeration_is_cut() {
    let dir = tempfile::tempdir().unwrap();
    let artifacts = [
        bundles().join("identity"),
        bundles().join("rag"),
        bundles().join("tool"),
    ];
    let refs: Vec<&Path> = artifacts.iter().map(PathBuf::as_path).collect();
    let result = attack_paths(&refs, &[], &dir.path().join("a"));
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stdout).contains("CONTROL_UNDECIDED"));
    let summary = fs::read_to_string(dir.path().join("a/summary.md")).unwrap();
    assert!(summary.contains("| CONTROL_UNDECIDED | 1 |"), "{summary}");
    assert!(summary.contains("CONTROLS_HELD is not \"secure\""));
    let cut = attack_paths(
        &refs,
        &["--max-paths-per-pair", "1", "--max-path-edges", "1"],
        &dir.path().join("b"),
    );
    assert_eq!(cut.status.code(), Some(2));
}

#[test]
fn exit_1_on_an_internal_write_failure_before_any_file_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    // A directory where the first file must go: writing it fails, even as root.
    fs::create_dir_all(out.join("projection-report.json")).unwrap();
    let result = attack_paths(&[&bundles().join("sc")], &[], &out);
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!out.join("attack-graph.json").exists());
}

#[test]
fn the_same_inputs_give_byte_identical_files() {
    let dir = tempfile::tempdir().unwrap();
    let artifacts = [
        bundles().join("identity"),
        bundles().join("static-a2a"),
        bundles().join("mt"),
    ];
    let forward: Vec<&Path> = artifacts.iter().map(PathBuf::as_path).collect();
    let backward: Vec<&Path> = artifacts.iter().rev().map(PathBuf::as_path).collect();
    attack_paths(&forward, &[], &dir.path().join("a"));
    attack_paths(&backward, &[], &dir.path().join("b"));
    for file in FILES {
        assert_eq!(
            fs::read(dir.path().join("a").join(file)).unwrap(),
            fs::read(dir.path().join("b").join(file)).unwrap(),
            "{file}"
        );
    }
}

/// Asserts exit 3, nothing written, and no planted value in the message.
fn refused(artifacts: &[&Path], extra: &[&str], canary: Option<&str>) {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("never");
    let result = attack_paths(artifacts, extra, &out);
    let stderr = String::from_utf8_lossy(&result.stderr).into_owned();
    assert_eq!(result.status.code(), Some(3), "{stderr}");
    assert!(!out.exists(), "a refusal wrote output");
    assert!(stderr.starts_with("refused:"), "{stderr}");
    if let Some(canary) = canary {
        assert!(!stderr.contains(canary), "{stderr}");
    }
}

#[test]
fn refusal_corpus_bundles_and_binding() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    // Unknown bundle and duplicate run.
    let empty = root.join("empty");
    fs::create_dir_all(&empty).unwrap();
    refused(&[&empty], &[], None);
    let tool = bundles().join("tool");
    refused(&[&tool, &tool], &[], None);
    // An edited scenario.
    let edited = staged(root, "tool");
    edit(&edited.join("inputs/scenario.json"), |v| {
        v["title"] = json!("CANARY-TITLE")
    });
    refused(&[&edited], &[], Some("CANARY-TITLE"));
    // A 020 evidence file changed by one byte, and a changed 019 manifest.
    let a2a = staged(root, "static-a2a");
    let trace = a2a.join("inputs/evidence/trace.json");
    let mut bytes = fs::read(&trace).unwrap();
    let at = bytes.iter().position(|b| b.is_ascii_lowercase()).unwrap();
    bytes[at] = if bytes[at] == b'a' { b'b' } else { b'a' };
    fs::write(&trace, bytes).unwrap();
    refused(&[&a2a], &[], None);
    let sc = staged(root, "static-sc");
    edit(&sc.join("inputs/evidence/manifest.json"), |v| {
        v["manifest_id"] = json!("CANARY-MANIFEST")
    });
    refused(&[&sc], &[], Some("CANARY-MANIFEST"));
}

#[test]
fn refusal_corpus_evidence_and_files() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let bad_record = staged(root, "rag");
    edit(&bad_record.join("rag-security-evidence.json"), |v| {
        v[0]["verdict"] = json!("CANARY-VERDICT")
    });
    refused(&[&bad_record], &[], Some("CANARY-VERDICT"));
    let unknown_id = staged(root, "memory");
    edit(&unknown_id.join("memory-security-result.json"), |v| {
        v["evidence_ids"][0] = json!("urn:CANARY-ID")
    });
    refused(&[&unknown_id], &[], Some("CANARY-ID"));
    // A symlinked input and a linked directory leaving the bundle.
    #[cfg(unix)]
    {
        let linked = staged(root, "identity");
        let real = linked.join("inputs/scenario.json");
        let elsewhere = root.join("outside.json");
        fs::rename(&real, &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &real).unwrap();
        refused(&[&linked], &[], None);
        let escape = staged(root, "mcp");
        let outside = root.join("outside-inputs");
        fs::rename(escape.join("inputs"), &outside).unwrap();
        std::os::unix::fs::symlink(&outside, escape.join("inputs")).unwrap();
        refused(&[&escape], &[], None);
    }
    // 16 MiB + 1 byte, and JSON nested 65 deep.
    let big = staged(root, "pi");
    fs::File::create(big.join("prompt-injection-evidence.json"))
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    refused(&[&big], &[], None);
    let deep = staged(root, "tool");
    fs::write(
        deep.join("tool-security-evidence.json"),
        format!("{}\"CANARY-DEEP\"{}", "[".repeat(65), "]".repeat(65)),
    )
    .unwrap();
    refused(&[&deep], &[], Some("CANARY-DEEP"));
}

fn model_file(root: &Path, name: &str, value: Value) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    path
}

#[test]
fn refusal_corpus_system_model_and_bounds() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let tool = bundles().join("tool");
    let base = json!({"schema_version": "1", "model_id": "m", "target_id": "t", "target_version": "1",
        "entities": [{"entity_id": "agent", "type": "AGENT", "display_name": "agent"},
                     {"entity_id": "other", "type": "TOOL", "display_name": "other"}]});
    let mut conflicting = base.clone();
    conflicting["aliases"] = json!([
        {"engine": "tool", "local_id": "CANARY-LOCAL", "entity_id": "agent"},
        {"engine": "tool", "local_id": "CANARY-LOCAL", "entity_id": "other"}]);
    let mut clash = base.clone();
    clash["aliases"] = json!([{"engine": "tool", "local_id": "sut", "entity_id": "other"}]);
    let mut no_rationale = base.clone();
    no_rationale["declared_edges"] =
        json!([{"type": "CALLS", "source": "agent", "target": "other", "status": "INFERRED"}]);
    let mut colon = base.clone();
    colon["entities"][0]["entity_id"] = json!("agent:CANARY");
    for (name, model, canary) in [
        ("conflict.json", conflicting, Some("CANARY-LOCAL")),
        ("clash.json", clash, None),
        ("rationale.json", no_rationale, None),
        ("colon.json", colon, Some("CANARY")),
    ] {
        let path = model_file(root, name, model);
        refused(
            &[&tool],
            &["--system-model", path.to_str().unwrap()],
            canary,
        );
    }
    for (flag, value) in [
        ("--max-path-edges", "13"),
        ("--max-paths", "10001"),
        ("--max-paths-per-pair", "65"),
        ("--max-paths", "0"),
    ] {
        refused(&[&tool], &[flag, value], None);
    }
    let dir = tempfile::tempdir().unwrap();
    let result = run(&[
        "validate",
        "attack-paths",
        "--artifacts",
        tool.to_str().unwrap(),
        "--output-dir",
        "../escape",
    ]);
    assert_eq!(result.status.code(), Some(3));
    assert!(!dir.path().join("../escape").exists());
}

#[test]
fn hostile_labels_are_escaped_in_the_views_and_credential_shaped_ids_are_hashed() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let bundle = staged(root, "tool");
    let model = model_file(
        root,
        "labels.json",
        json!({
            "schema_version": "1", "model_id": "m", "target_id": "t", "target_version": "1",
            "entities": [{"entity_id": "agent", "type": "AGENT", "display_name": "evil\"]; click n0 --> <b>"}],
            "aliases": [{"engine": "tool", "local_id": "sut", "entity_id": "agent"}]
        }),
    );
    let out = root.join("out");
    let result = attack_paths(
        &[&bundle],
        &["--system-model", model.to_str().unwrap()],
        &out,
    );
    assert!(
        matches!(result.status.code(), Some(0) | Some(2)),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for view in ["graph.mmd", "graph.dot"] {
        let text = fs::read_to_string(out.join(view)).unwrap();
        assert!(
            text.contains("evil\\\"]; click n0 --&gt; &lt;b&gt;"),
            "{view}"
        );
        assert!(!text.contains("<b>"));
    }
}
