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

/// A stdio server that, like most real ones, needs a variable from the
/// operator's environment: it refuses to start without it, then execs the lab.
#[cfg(unix)]
fn env_dependent_server(dir: &std::path::Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let script = dir.join("client-mcp.py");
    std::fs::write(
        &script,
        "#!/usr/bin/env python3\nimport os, sys\n\
         if not os.environ.get('CLIENT_API_KEY'):\n    sys.exit('CLIENT_API_KEY missing')\n\
         os.execv(os.environ['MCP_BIN'], [os.environ['MCP_BIN']])\n",
    )
    .expect("write server");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    script
}

#[cfg(unix)]
#[test]
fn pass_env_hands_named_variables_to_the_server_and_writes_no_value() {
    let lab = compile_dependent_lab();
    let dir = tempfile::tempdir().expect("tempdir");
    let server = env_dependent_server(dir.path());
    let server = server.to_string_lossy();
    let out = dir.path().join("out");
    let discover = |pass: &[&str]| {
        let mut args = vec!["discover", "--stdio", "--json", "--target-id", "client"];
        for name in pass {
            args.extend(["--pass-env", name]);
        }
        let out = out.to_string_lossy().into_owned();
        Command::new(cli_bin())
            .args(&args)
            .args(["--output-dir", &out, "--", server.as_ref()])
            .env("CLIENT_API_KEY", PLANTED)
            .env("MCP_BIN", &lab)
            .output()
            .expect("spawn CLI")
    };

    // Nothing is inherited by default: the server cannot start.
    let refused = discover(&[]);
    assert_ne!(code(&refused), 0);

    let output = discover(&["PATH", "MCP_BIN", "CLIENT_API_KEY"]);
    assert_eq!(code(&output), 0, "stderr={}", stderr_str(&output));
    let inventory: Value = serde_json::from_str(&stdout_str(&output)).expect("json");
    assert_eq!(inventory["tools"].as_array().map(Vec::len), Some(8));

    // The value is never written: not to stdout, stderr or any artifact.
    let mut written = format!("{}{}", stdout_str(&output), stderr_str(&output));
    for entry in walkdir(&out) {
        written.push_str(&std::fs::read_to_string(entry).unwrap_or_default());
    }
    assert!(!written.contains(PLANTED), "the passed value leaked");
}

#[cfg(unix)]
fn walkdir(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(walkdir(&path));
        } else {
            files.push(path);
        }
    }
    files
}

#[test]
fn pass_env_is_refused_for_url_targets_and_bad_names() {
    let output = run(&[
        "discover",
        "--url",
        "https://mcp.example.test/mcp",
        "--pass-env",
        "PATH",
    ]);
    assert_eq!(code(&output), 3);
    assert!(stderr_str(&output).contains("--pass-env applies only to --stdio"));
    for bad in ["A=B", "1X", "PATH;id"] {
        let output = run(&[
            "discover",
            "--stdio",
            "--pass-env",
            bad,
            "--",
            "synthetic-mcp",
        ]);
        assert_eq!(code(&output), 3, "{bad}");
    }
}
