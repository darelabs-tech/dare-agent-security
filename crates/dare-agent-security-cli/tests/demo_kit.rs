//! The one-command demo (`demo/run-demo.sh`) runs end to end and tells the
//! story its report claims. It is run here so the demo cannot drift from the
//! engines: a lab or engine change that alters the story fails this test.
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dare-agent-security"))
}

fn synthetic_mcp_bin() -> PathBuf {
    let sibling =
        cli_bin().with_file_name(format!("synthetic-mcp{}", std::env::consts::EXE_SUFFIX));
    if sibling.is_file() {
        return sibling;
    }
    let fallback = repo().join("target/debug/synthetic-mcp");
    assert!(
        fallback.is_file(),
        "synthetic-mcp was not built; run `cargo build --workspace --bins` first"
    );
    fallback
}

fn demo(args: &[&str]) -> Output {
    Command::new("sh")
        .arg(repo().join("demo/run-demo.sh"))
        .args(args)
        .env("DARE_BIN", cli_bin())
        .env("SYNTHETIC_MCP_BIN", synthetic_mcp_bin())
        .output()
        .expect("run demo")
}

/// A demo output directory under `target/`, removed when dropped.
struct OutDir(String);

impl OutDir {
    fn new(name: &str) -> Self {
        let rel = format!("target/demo-kit-{name}-{}", std::process::id());
        let _ = fs::remove_dir_all(repo().join(&rel));
        Self(rel)
    }
    fn path(&self) -> PathBuf {
        repo().join(&self.0)
    }
}

impl Drop for OutDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.path());
    }
}

fn json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
        .expect("json")
}

#[test]
fn the_demo_tells_the_before_after_and_runtime_story() {
    let out = OutDir::new("story");
    let run = demo(&["--output-dir", &out.0]);
    assert!(
        run.status.success(),
        "demo failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let summary = json(&out.path().join("demo-summary.json"));

    let before = &summary["before"];
    assert!(before["engines"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["verdict"] == "FAIL"));
    let paths = before["paths"].as_array().unwrap();
    assert_eq!(paths.len(), 4);
    assert!(paths.iter().all(|p| p["control"] == "CONTROL_FAILED"));
    assert_eq!(before["exposed"], 4);
    assert_eq!(before["by_class"]["PRIVILEGED_CREDENTIAL"], 2);
    assert_eq!(before["by_class"]["CROSS_TENANT_RESOURCE"], 2);

    let after = &summary["after"];
    assert!(after["engines"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["verdict"] == "PASS"));
    assert!(after["paths"]
        .as_array()
        .unwrap()
        .iter()
        .all(|p| p["control"] == "CONTROLS_HELD"));
    assert_eq!(after["exposed"], 0);

    assert_eq!(summary["runtime"]["attack"]["verdict"], "FAIL");
    assert_eq!(summary["runtime"]["clean"]["verdict"], "PASS");
    assert_eq!(summary["inventory"]["tools"], 8);

    let md = fs::read_to_string(out.path().join("REPORT.md")).unwrap();
    assert!(md.contains("## What this demo does not claim"));
    let html = fs::read_to_string(out.path().join("report.html")).unwrap();
    assert!(html.starts_with("<!doctype html>"));
    // Self-contained and inert: no script, no remote resource.
    assert!(!html.contains("<script") && !html.contains("http://") && !html.contains("https://"));

    // A second run replaces the directory it wrote itself.
    assert!(demo(&["--output-dir", &out.0]).status.success());
}

#[test]
fn the_demo_never_writes_outside_the_repository_or_over_foreign_files() {
    for bad in ["../escape", "/tmp/x", "-x", ""] {
        let run = demo(&["--output-dir", bad]);
        assert_eq!(run.status.code(), Some(3), "{bad}");
    }
    // A non-empty directory the demo did not create is left alone.
    let run = demo(&["--output-dir", "crates"]);
    assert_eq!(run.status.code(), Some(3));
    assert!(repo()
        .join("crates/dare-agent-security-cli/Cargo.toml")
        .is_file());
    assert!(demo(&["--bogus"]).status.code() == Some(3));
}
