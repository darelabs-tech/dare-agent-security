//! CLI E2E matrix: stdio discovery against the synthetic lab with method traces.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use dare_mcp_discovery::{validate, Completeness, DiscoveryInventory, PolicyProfile};
use serde_json::Value;

const CANARY: &str = "sk_live_PLANTED_SECRET_VALUE_9f3a";
const FORBIDDEN: &[&str] = &["tools/call", "resources/read", "prompts/get", "ping"];

fn cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dare-agent-security"))
}

fn synthetic_mcp_bin() -> PathBuf {
    let mut path = cli_bin();
    path.pop();
    path.push(format!("synthetic-mcp{}", std::env::consts::EXE_SUFFIX));
    if path.is_file() {
        return path;
    }
    let fallback = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/debug")
        .join(format!("synthetic-mcp{}", std::env::consts::EXE_SUFFIX));
    assert!(
        fallback.is_file(),
        "synthetic-mcp binary missing; run `cargo test --workspace`"
    );
    fallback
}

fn unique_trace_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("dare-c002-cli-trace-{nanos}.json"))
}

fn run_discover(args: &[&str], trace: &Path, extra_env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(cli_bin());
    command
        .env("SYNTHETIC_MCP_TRACE_PATH", trace)
        .env("MCP_AUTH_TOKEN", CANARY)
        .args(args);
    for (key, value) in extra_env {
        command.env(key, value);
    }
    command
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

fn read_trace(path: &Path) -> Vec<String> {
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    if raw.trim().is_empty() {
        return Vec::new();
    }
    serde_json::from_str(&raw).unwrap_or_else(|_| {
        raw.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    })
}

fn assert_passive_trace(methods: &[String]) {
    let allow = PolicyProfile::Current2026_07_28.allowlisted_methods();
    for method in methods {
        assert!(
            allow.contains(&method.as_str()),
            "lab received {method} outside Cycle002Allowlist {allow:?}; trace={methods:?}"
        );
        assert!(
            !FORBIDDEN.contains(&method.as_str()),
            "forbidden method reached the lab: {method}; trace={methods:?}"
        );
        assert!(!method.contains(CANARY));
    }
}

fn names_from(
    inventory: &DiscoveryInventory,
) -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    (
        inventory
            .tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect(),
        inventory
            .resources
            .iter()
            .map(|resource| resource.uri.clone())
            .collect(),
        inventory
            .prompts
            .iter()
            .map(|prompt| prompt.name.clone())
            .collect(),
    )
}

fn assert_no_canary(output: &Output, inventory_json: &str) {
    let stdout = stdout_str(output);
    let stderr = stderr_str(output);
    assert!(!stdout.contains(CANARY), "stdout leaked canary");
    assert!(!stderr.contains(CANARY), "stderr leaked canary");
    assert!(!inventory_json.contains(CANARY), "inventory leaked canary");
}

#[test]
fn stdio_current_protocol_trace_is_subset_of_allowlist() {
    let lab = synthetic_mcp_bin();
    let lab = lab.to_string_lossy();
    let trace = unique_trace_path();
    let output = run_discover(
        &[
            "discover",
            "--stdio",
            "--json",
            "--target-id",
            "synthetic-rental-mcp",
            "--",
            lab.as_ref(),
        ],
        &trace,
        &[],
    );
    assert_eq!(code(&output), 0, "stderr={}", stderr_str(&output));
    let stdout = stdout_str(&output);
    assert_no_canary(&output, &stdout);
    let inventory: DiscoveryInventory =
        serde_json::from_str(stdout.trim()).expect("inventory json");
    validate(&inventory).expect("validate");
    assert_eq!(inventory.completeness, Completeness::Complete);
    let methods = read_trace(&trace);
    assert!(
        !methods.is_empty(),
        "expected SYNTHETIC_MCP_TRACE_PATH dump at {}",
        trace.display()
    );
    assert_passive_trace(&methods);
    assert!(
        methods.iter().any(|method| method == "server/discover"),
        "expected server/discover in {methods:?}"
    );
    assert!(methods.iter().any(|method| method == "tools/list"));
    let _ = std::fs::remove_file(&trace);
}

#[test]
fn max_pages_bound_exits_partial_and_stays_passive() {
    let lab = synthetic_mcp_bin();
    let lab = lab.to_string_lossy();
    let trace = unique_trace_path();
    let output = run_discover(
        &[
            "discover",
            "--stdio",
            "--json",
            "--max-pages",
            "1",
            "--target-id",
            "synthetic-rental-mcp",
            "--",
            lab.as_ref(),
        ],
        &trace,
        &[],
    );
    assert_eq!(code(&output), 2, "stderr={}", stderr_str(&output));
    let stdout = stdout_str(&output);
    assert_no_canary(&output, &stdout);
    let inventory: DiscoveryInventory =
        serde_json::from_str(stdout.trim()).expect("inventory json");
    assert_eq!(inventory.completeness, Completeness::Partial);
    validate(&inventory).expect("partial still validates");
    assert_passive_trace(&read_trace(&trace));
    let _ = std::fs::remove_file(&trace);
}

#[test]
fn credential_canary_is_absent_from_cli_streams() {
    let url = format!("https://bearer:{CANARY}@mcp.example.test/mcp");
    let trace = unique_trace_path();
    let output = run_discover(&["discover", "--json", "--url", &url], &trace, &[]);
    assert_eq!(code(&output), 3);
    assert!(stdout_str(&output).trim().is_empty());
    assert_no_canary(&output, "");
    assert!(!stderr_str(&output).contains("bearer:"));

    let lab = synthetic_mcp_bin();
    let lab = lab.to_string_lossy();
    let ok = run_discover(
        &[
            "discover",
            "--stdio",
            "--json",
            "--target-id",
            "synthetic-rental-mcp",
            "--",
            lab.as_ref(),
        ],
        &trace,
        &[("AUTHORIZATION", &format!("Bearer {CANARY}"))],
    );
    assert_eq!(code(&ok), 0, "stderr={}", stderr_str(&ok));
    assert_no_canary(&ok, &stdout_str(&ok));
    let _ = std::fs::remove_file(&trace);
}

#[test]
fn repeated_scans_normalize_catalog_names() {
    let lab = synthetic_mcp_bin();
    let lab = lab.to_string_lossy();
    let first_trace = unique_trace_path();
    let second_trace = unique_trace_path();
    let args = [
        "discover",
        "--stdio",
        "--json",
        "--target-id",
        "synthetic-rental-mcp",
        "--",
        lab.as_ref(),
    ];
    let first = run_discover(&args, &first_trace, &[]);
    let second = run_discover(&args, &second_trace, &[]);
    assert_eq!(code(&first), 0, "stderr={}", stderr_str(&first));
    assert_eq!(code(&second), 0, "stderr={}", stderr_str(&second));
    let left: DiscoveryInventory = serde_json::from_str(stdout_str(&first).trim()).expect("first");
    let right: DiscoveryInventory =
        serde_json::from_str(stdout_str(&second).trim()).expect("second");
    assert_ne!(left.generated_at, right.generated_at);
    assert_eq!(names_from(&left), names_from(&right));
    assert_passive_trace(&read_trace(&first_trace));
    assert_passive_trace(&read_trace(&second_trace));
    let _ = std::fs::remove_file(&first_trace);
    let _ = std::fs::remove_file(&second_trace);
}

#[test]
fn json_value_has_no_recursive_live_uris() {
    let lab = synthetic_mcp_bin();
    let lab = lab.to_string_lossy();
    let trace = unique_trace_path();
    let output = run_discover(
        &[
            "discover",
            "--stdio",
            "--json",
            "--target-id",
            "synthetic-rental-mcp",
            "--",
            lab.as_ref(),
        ],
        &trace,
        &[],
    );
    assert_eq!(code(&output), 0, "stderr={}", stderr_str(&output));
    let value: Value = serde_json::from_str(stdout_str(&output).trim()).expect("json");
    let encoded = value.to_string();
    assert!(!encoded.contains("https://schemas.example.test") || encoded.contains("$ref"));
    assert!(!encoded.contains("http://"));
    assert_passive_trace(&read_trace(&trace));
    let _ = std::fs::remove_file(&trace);
}
