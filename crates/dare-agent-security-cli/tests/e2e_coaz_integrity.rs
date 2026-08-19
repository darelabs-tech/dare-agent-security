//! CLI end-to-end proof for `validate coaz-integrity` (Cycle 003 task-011).

use std::path::PathBuf;
use std::process::{Command, Output};

use dare_coaz_integrity::{validate_result, IntegrityVerdict, VectorResult, BUILTIN_VECTOR_IDS};

const MUTATION_VECTOR_IDS: &[&str] = &[
    "COAZ-INTEGRITY-002",
    "COAZ-INTEGRITY-003",
    "COAZ-INTEGRITY-004",
    "COAZ-INTEGRITY-005",
];

const CANARY_URL_USER: &str = "canaryUser_7f3a";
const CANARY_URL_PASS: &str = "canaryPass_7f3a";
const CANARY_BEARER: &str = "canaryBearer_7f3a";
const CANARY_APIKEY: &str = "canaryApiKey_7f3a";

fn cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dare-agent-security"))
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

fn assert_no_canary(label: &str, text: &str) {
    for canary in [
        CANARY_URL_USER,
        CANARY_URL_PASS,
        CANARY_BEARER,
        CANARY_APIKEY,
    ] {
        assert!(
            !text.contains(canary),
            "{label} leaked canary `{canary}`: {text}"
        );
    }
}

fn assert_streams_clean(output: &Output) {
    assert_no_canary("stdout", &stdout_str(output));
    assert_no_canary("stderr", &stderr_str(output));
}

#[test]
fn cli_vulnerable_mode_proves_fail_for_each_mutation_vector() {
    for vector_id in MUTATION_VECTOR_IDS {
        let output = run(&[
            "validate",
            "coaz-integrity",
            "--fixture",
            vector_id,
            "--reference-mode",
            "vulnerable",
            "--json",
        ]);
        assert_eq!(
            code(&output),
            2,
            "{vector_id} stderr={}",
            stderr_str(&output)
        );
        assert_streams_clean(&output);

        let result: VectorResult =
            serde_json::from_str(stdout_str(&output).trim()).expect("parse result");
        validate_result(&result).expect("result contract");
        assert_eq!(result.vector_id, *vector_id);
        assert_eq!(result.verdict, IntegrityVerdict::Fail);
        assert!(result.sink_receipt.forwarded);
    }
}

#[test]
fn cli_secure_mode_proves_pass_for_each_mutation_vector() {
    for vector_id in MUTATION_VECTOR_IDS {
        let output = run(&[
            "validate",
            "coaz-integrity",
            "--fixture",
            vector_id,
            "--json",
        ]);
        assert_eq!(
            code(&output),
            0,
            "{vector_id} stderr={}",
            stderr_str(&output)
        );
        assert_streams_clean(&output);

        let result: VectorResult =
            serde_json::from_str(stdout_str(&output).trim()).expect("parse result");
        validate_result(&result).expect("result contract");
        assert_eq!(result.vector_id, *vector_id);
        assert_eq!(result.verdict, IntegrityVerdict::Pass);
        assert_ne!(
            result.initial_binding.digest, result.final_binding.digest,
            "{vector_id} must change binding"
        );
    }
}

#[test]
fn cli_secure_all_and_vulnerable_all_aggregate_expected_exits() {
    let secure = run(&["validate", "coaz-integrity", "--all"]);
    assert_eq!(code(&secure), 0, "stderr={}", stderr_str(&secure));
    assert_streams_clean(&secure);

    let vulnerable = run(&[
        "validate",
        "coaz-integrity",
        "--all",
        "--reference-mode",
        "vulnerable",
    ]);
    assert_eq!(code(&vulnerable), 2, "stderr={}", stderr_str(&vulnerable));
    assert_streams_clean(&vulnerable);
}

#[test]
fn cli_streams_and_artifacts_contain_no_canary_secrets() {
    let dir = std::env::temp_dir().join(format!("dare-coaz-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let output = Command::new(cli_bin())
        .args([
            "validate",
            "coaz-integrity",
            "--all",
            "--evidence-dir",
            dir.to_str().expect("temp path utf8"),
        ])
        .env("MCP_AUTH_TOKEN", CANARY_BEARER)
        .env("API_KEY", CANARY_APIKEY)
        .output()
        .expect("spawn CLI");
    assert_eq!(code(&output), 0, "stderr={}", stderr_str(&output));
    assert_streams_clean(&output);

    for vector_id in BUILTIN_VECTOR_IDS {
        let result_path = dir.join(format!("{vector_id}.result.json"));
        let evidence_path = dir.join(format!("{vector_id}.evidence.json"));
        let result_text = std::fs::read_to_string(&result_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", result_path.display()));
        let evidence_text = std::fs::read_to_string(&evidence_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", evidence_path.display()));
        assert_no_canary(&format!("{vector_id} result artifact"), &result_text);
        assert_no_canary(&format!("{vector_id} evidence artifact"), &evidence_text);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_builtin_matrix_covers_all_vector_ids() {
    let output = run(&["validate", "coaz-integrity", "--all", "--json"]);
    assert_eq!(code(&output), 0, "stderr={}", stderr_str(&output));
    let results: Vec<VectorResult> =
        serde_json::from_str(stdout_str(&output).trim()).expect("parse results");
    assert_eq!(results.len(), BUILTIN_VECTOR_IDS.len());
    for (index, vector_id) in BUILTIN_VECTOR_IDS.iter().enumerate() {
        assert_eq!(results[index].vector_id, *vector_id);
        assert_eq!(results[index].verdict, IntegrityVerdict::Pass);
    }
}
