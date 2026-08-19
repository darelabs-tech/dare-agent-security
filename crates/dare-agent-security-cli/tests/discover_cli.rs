//! CLI contract tests for `dare-agent-security discover`.

use std::path::PathBuf;
use std::process::{Command, Output};

use dare_mcp_discovery::{validate, Completeness, DiscoveryInventory};
use serde_json::Value;

const PLANTED: &str = "sk_live_PLANTED_SECRET_VALUE_9f3a";

fn cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dare-agent-security"))
}

fn synthetic_mcp_bin() -> Option<PathBuf> {
    let mut path = cli_bin();
    path.pop();
    path.push(format!("synthetic-mcp{}", std::env::consts::EXE_SUFFIX));
    if path.is_file() {
        return Some(path);
    }
    let fallback = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/debug")
        .join(format!("synthetic-mcp{}", std::env::consts::EXE_SUFFIX));
    fallback.is_file().then_some(fallback)
}

fn compile_dependent_lab() -> PathBuf {
    synthetic_mcp_bin().unwrap_or_else(|| {
        panic!(
            "synthetic-mcp binary was not found next to {} or in target/debug; run `cargo test --workspace` so workspace bins are compiled",
            cli_bin().display()
        );
    })
}

fn run(args: &[&str]) -> Output {
    Command::new(cli_bin())
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to spawn CLI: {err}"))
}

fn stdout_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("process exit code")
}

#[test]
fn stdio_and_url_are_mutually_exclusive() {
    let output = run(&[
        "discover",
        "--stdio",
        "--url",
        "https://mcp.example.test/mcp",
        "--",
        "synthetic-mcp",
    ]);
    assert_ne!(code(&output), 0, "conflicting modes must fail");
    assert_eq!(code(&output), 3);
    assert!(stdout_str(&output).trim().is_empty());
    let stderr = stderr_str(&output);
    assert!(
        stderr.contains("cannot be used with")
            || stderr.contains("mutually exclusive")
            || stderr.contains("conflict"),
        "stderr should explain the conflict: {stderr}"
    );
}

#[test]
fn help_documents_exit_codes_and_omits_credential_flags() {
    let output = run(&["discover", "--help"]);
    assert_eq!(code(&output), 0);
    let help = format!("{}{}", stdout_str(&output), stderr_str(&output));
    assert!(help.contains("--stdio"));
    assert!(help.contains("--url"));
    assert!(help.contains("--json"));
    assert!(help.contains("Exit codes"));
    assert!(!help.contains("--token"));
    assert!(!help.contains("--password"));
    assert!(!help.contains("--credential"));
}

#[test]
fn json_stdout_is_only_a_json_object() {
    let lab = compile_dependent_lab();
    let lab = lab.to_string_lossy();
    let output = run(&[
        "discover",
        "--stdio",
        "--json",
        "--target-id",
        "synthetic-rental-mcp",
        "--",
        lab.as_ref(),
    ]);
    assert_eq!(code(&output), 0, "stderr={}", stderr_str(&output));
    let stdout = stdout_str(&output);
    let trimmed = stdout.trim();
    assert!(
        trimmed.starts_with('{'),
        "stdout must be a JSON object: {stdout}"
    );
    let inventory: DiscoveryInventory =
        serde_json::from_str(trimmed).expect("stdout must parse as DiscoveryInventory");
    validate(&inventory).expect("canonical inventory must validate");
    let value: Value = serde_json::from_str(trimmed).expect("json value");
    assert!(value.is_object());
}

#[test]
fn human_mode_writes_summary_not_raw_json() {
    let lab = compile_dependent_lab();
    let lab = lab.to_string_lossy();
    let output = run(&[
        "discover",
        "--stdio",
        "--target-id",
        "synthetic-rental-mcp",
        "--",
        lab.as_ref(),
    ]);
    assert_eq!(code(&output), 0, "stderr={}", stderr_str(&output));
    let stdout = stdout_str(&output);
    let trimmed = stdout.trim();
    assert!(
        !trimmed.starts_with('{'),
        "human mode must not write raw JSON: {stdout}"
    );
    assert!(stdout.contains("DARE Agent Security"));
    assert!(stdout.contains("Target"));
    assert!(stdout.contains("synthetic-rental-mcp"));
    assert!(stdout.contains("Protocol"));
    assert!(stdout.contains("stdio"));
}

#[test]
fn json_failure_keeps_stdout_clean_and_diagnostics_on_stderr() {
    let url = format!("https://bearer:{PLANTED}@mcp.example.test/mcp");
    let output = run(&["discover", "--json", "--url", &url]);
    assert_eq!(code(&output), 3);
    assert!(
        stdout_str(&output).trim().is_empty(),
        "json mode must not mix diagnostics into stdout: {}",
        stdout_str(&output)
    );
    let stderr = stderr_str(&output);
    assert!(!stderr.trim().is_empty(), "failure must diagnose on stderr");
    assert!(!stderr.contains(PLANTED), "stderr leaked planted secret");
    assert!(!stderr.contains("bearer:"), "stderr leaked url userinfo");
}

#[test]
fn partial_max_pages_exits_two() {
    let lab = compile_dependent_lab();
    let lab = lab.to_string_lossy();
    let output = run(&[
        "discover",
        "--stdio",
        "--json",
        "--max-pages",
        "1",
        "--target-id",
        "synthetic-rental-mcp",
        "--",
        lab.as_ref(),
    ]);
    assert_eq!(code(&output), 2, "stderr={}", stderr_str(&output));
    let inventory: DiscoveryInventory =
        serde_json::from_str(stdout_str(&output).trim()).expect("inventory json");
    assert_eq!(inventory.completeness, Completeness::Partial);
    validate(&inventory).expect("partial inventory must still validate");
}

#[test]
fn bad_url_exits_unsupported() {
    let cleartext = run(&["discover", "--url", "http://mcp.example.test/mcp"]);
    assert_eq!(code(&cleartext), 3, "stderr={}", stderr_str(&cleartext));
    assert!(stdout_str(&cleartext).trim().is_empty());
}

#[test]
fn missing_stdio_program_exits_unsupported() {
    let output = run(&["discover", "--stdio"]);
    assert_eq!(code(&output), 3, "stderr={}", stderr_str(&output));
    assert!(stdout_str(&output).trim().is_empty());
}

#[test]
fn cycle_002_operator_docs_exist() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for rel in [
        "README.md",
        "crates/dare-mcp-discovery/README.md",
        "crates/dare-agent-security-cli/EXIT.md",
        "docs/inventory-v1.md",
        "docs/passive-policy.md",
        "docs/synthetic-lab.md",
        "docs/mcp-compatibility.md",
        "DARE/cycles/002-mcp-discovery-baseline/PROOF.md",
        ".github/workflows/ci.yml",
    ] {
        assert!(
            root.join(rel).is_file(),
            "Cycle 002 operator/docs artifact missing: {rel}"
        );
    }
}

#[test]
fn missing_executable_exits_scanner_error() {
    let output = run(&[
        "discover",
        "--stdio",
        "--json",
        "--",
        "__dare_agent_security_missing_mcp_server__",
    ]);
    assert_eq!(code(&output), 1, "stderr={}", stderr_str(&output));
    assert!(stdout_str(&output).trim().is_empty());
    assert!(!stderr_str(&output).trim().is_empty());
}
