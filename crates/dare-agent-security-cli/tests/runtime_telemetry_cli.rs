//! `validate runtime-telemetry` at the process boundary (Cycle 025 task-022).
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::{json, Value};

const FILES: [&str; 4] = [
    "runtime-telemetry-evidence.json",
    "runtime-telemetry-findings.json",
    "runtime-telemetry-result.json",
    "summary.md",
];

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dare-agent-security"))
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("binary runs")
}

fn span(trace: &str, id: &str, parent: Option<&str>, start: u64, attrs: &[(&str, &str)]) -> Value {
    let mut s = json!({
        "traceId": format!("{trace:0>32}"),
        "spanId": format!("{id:0>16}"),
        "name": "span",
        "kind": 1,
        "flags": 1,
        "startTimeUnixNano": start.to_string(),
        "endTimeUnixNano": (start + 10).to_string(),
        "attributes": attrs
            .iter()
            .map(|(k, v)| json!({"key": k, "value": {"stringValue": v}}))
            .collect::<Vec<_>>(),
        "status": {"code": 0}
    });
    if let Some(p) = parent {
        s["parentSpanId"] = json!(format!("{p:0>16}"));
    }
    s
}

/// A trace whose agent calls `tool` as `user-7`.
fn trace(t: &str, tool: &str, extra: &[(&str, &str)]) -> Value {
    let mut agent_attrs = vec![
        ("gen_ai.operation.name", "invoke_agent"),
        ("gen_ai.agent.name", "assistant"),
        ("user.id", "user-7"),
    ];
    agent_attrs.extend_from_slice(extra);
    json!({"resourceSpans": [{
        "resource": {"attributes": []},
        "scopeSpans": [{"scope": {"name": "cli-test"}, "spans": [
            span(t, "a", None, 10, &agent_attrs),
            span(t, "b", Some("a"), 20, &[
                ("gen_ai.operation.name", "execute_tool"),
                ("gen_ai.tool.name", tool),
                ("user.id", "user-7"),
            ]),
        ]}]
    }]})
}

fn policy() -> Value {
    json!({
        "schema_version": "1", "policy_id": "support-desk", "content_capture_allowed": false,
        "principal_keys": ["user.id"], "tenant_keys": ["tenant.id"],
        "required_operations": ["TOOL_EXEC"],
        "agents": [{"name": "assistant", "allowed_tools": ["search"], "principal": "user-7"}]
    })
}

fn write(root: &Path, name: &str, value: &Value) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    path
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn validate(traces: &[&Path], policy: Option<&Path>, extra: &[&str], out: &Path) -> Output {
    let mut args: Vec<String> = vec!["validate".into(), "runtime-telemetry".into()];
    for t in traces {
        args.push("--traces".into());
        args.push(t.to_str().unwrap().into());
    }
    if let Some(p) = policy {
        args.push("--policy".into());
        args.push(p.to_str().unwrap().into());
    }
    args.push("--output-dir".into());
    args.push(out.to_str().unwrap().into());
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&refs)
}

#[test]
fn help_names_every_flag_and_offers_no_network_or_exec_flag() {
    let help = String::from_utf8(run(&["validate", "runtime-telemetry", "--help"]).stdout).unwrap();
    let mut flags: Vec<&str> = help
        .split_whitespace()
        .filter(|w| w.starts_with("--"))
        .map(|w| w.trim_end_matches(','))
        .collect();
    flags.sort();
    flags.dedup();
    assert_eq!(
        flags,
        [
            "--help",
            "--json",
            "--max-spans",
            "--output-dir",
            "--policy",
            "--traces"
        ]
    );
    for code in [
        "0  every judged property is PASS",
        "2  a property is FAIL",
        "3  refusal",
    ] {
        assert!(help.contains(code), "{code}");
    }
    assert!(help.contains("self-reported") && help.contains("absent span is never evidence"));
    for forbidden in [
        "--endpoint",
        "--listen",
        "--port",
        "--collector",
        "--otlp-endpoint",
        "--header",
        "--token",
        "--exec",
        "--mode",
    ] {
        let out = run(&["validate", "runtime-telemetry", forbidden, "x"]);
        assert_ne!(out.status.code(), Some(0), "{forbidden} accepted");
        assert!(!help.contains(forbidden), "{forbidden} is offered");
    }
}

#[test]
fn exit_0_writes_the_four_files_when_every_judged_property_passes() {
    let root = tempfile::tempdir().unwrap();
    let t = write(root.path(), "t.json", &trace("1", "search", &[]));
    let p = write(root.path(), "p.json", &policy());
    let out = root.path().join("out");
    let result = validate(&[&t], Some(&p), &["--json"], &out);
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(names(&out), FILES);
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("\"engine\": \"runtime-telemetry\""));
    assert!(
        stdout.ends_with(
            "1 trace(s), 2 span(s): PASS (every_judged_property_passed); 4 of 9 properties judged\n"
        ),
        "{stdout}"
    );
    // The evidence file carries valid Cycle 001 records.
    let evidence: Value =
        serde_json::from_slice(&fs::read(out.join("runtime-telemetry-evidence.json")).unwrap())
            .unwrap();
    let records = evidence["records"].as_array().unwrap();
    assert!(!records.is_empty());
    for r in records {
        let record: dare_security_evidence::SecurityEvidence =
            serde_json::from_value(r.clone()).unwrap();
        dare_security_evidence::validate(&record).unwrap();
    }
    assert_eq!(evidence["executions"]["evidence_class"], "TRACE");
    assert_eq!(
        evidence["coverage"]["profile"]["id"],
        "runtime-telemetry-baseline-2026"
    );
}

#[test]
fn exit_2_on_a_violation_or_when_nothing_can_be_judged() {
    let root = tempfile::tempdir().unwrap();
    let bad = write(root.path(), "bad.json", &trace("1", "delete_all", &[]));
    let p = write(root.path(), "p.json", &policy());
    let out = root.path().join("fail");
    let result = validate(&[&bad], Some(&p), &[], &out);
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8(result.stdout)
        .unwrap()
        .contains(": FAIL (a_property_failed)"));
    let findings: Value =
        serde_json::from_slice(&fs::read(out.join("runtime-telemetry-findings.json")).unwrap())
            .unwrap();
    assert!(findings["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["rule"] == "B-1" && f["verdict"] == "FAIL"));
    // An export with no span judges nothing: INCONCLUSIVE, never a pass.
    let empty = write(root.path(), "empty.json", &json!({"resourceSpans": []}));
    let out = root.path().join("empty");
    let result = validate(&[&empty], None, &[], &out);
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8(result.stdout)
        .unwrap()
        .contains("INCONCLUSIVE (nothing_judged)"));
}

#[test]
fn exit_3_on_a_refusal_writes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let good = write(root.path(), "good.json", &trace("1", "search", &[]));
    let mut doctored = trace("2", "search", &[]);
    doctored["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["kind"] = json!("SPAN_KIND_CLIENT");
    let doctored = write(root.path(), "doctored.json", &doctored);
    let bad_policy = write(
        root.path(),
        "bad-policy.json",
        &json!({"schema_version": "1"}),
    );
    let missing = root.path().join("missing.json");
    let out = root.path().join("out");
    let cases: Vec<(Vec<&Path>, Option<&Path>, Vec<&str>)> = vec![
        (vec![&good, &doctored], None, vec![]),
        (vec![&good], Some(&bad_policy), vec![]),
        (vec![&good], None, vec!["--max-spans", "0"]),
        (vec![&good], None, vec!["--max-spans", "1000001"]),
        (vec![&missing], None, vec![]),
    ];
    for (traces, policy, extra) in cases {
        let result = validate(&traces, policy, &extra, &out);
        assert_eq!(
            result.status.code(),
            Some(3),
            "{extra:?} {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!out.exists(), "{extra:?} wrote");
    }
    // The refusal names the position, never the path or the content.
    let result = validate(&[&good, &doctored], None, &[], &out);
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("trace file 1"), "{stderr}");
    assert!(!stderr.contains("doctored") && !stderr.contains("SPAN_KIND_CLIENT"));
}

#[test]
fn exit_1_on_an_internal_write_failure() {
    let root = tempfile::tempdir().unwrap();
    let t = write(root.path(), "t.json", &trace("1", "search", &[]));
    let out = root.path().join("out");
    // A directory where the first file must go: writing it fails, even as root.
    fs::create_dir_all(out.join("runtime-telemetry-result.json")).unwrap();
    let result = validate(&[&t], None, &[], &out);
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!out.join("summary.md").exists());
}

#[test]
fn no_attribute_value_reaches_any_file_or_stdout() {
    let root = tempfile::tempdir().unwrap();
    let leaky = trace(
        "1",
        "delete_all",
        &[
            ("note", "CANARY-CLI-NOTE-2b7f91"),
            ("http.request.header.x-canary", "CANARY-CLI-HEADER-55ae"),
        ],
    );
    let t = write(root.path(), "t.json", &leaky);
    let p = write(root.path(), "p.json", &policy());
    let out = root.path().join("out");
    let result = validate(&[&t], Some(&p), &["--json"], &out);
    assert_eq!(result.status.code(), Some(2));
    let mut all = String::from_utf8(result.stdout).unwrap();
    all.push_str(&String::from_utf8(result.stderr).unwrap());
    for f in FILES {
        all.push_str(&fs::read_to_string(out.join(f)).unwrap());
    }
    for planted in [
        "CANARY-CLI-NOTE-2b7f91",
        "CANARY-CLI-HEADER-55ae",
        "user-7",
        "delete_all",
        "assistant",
    ] {
        assert!(!all.contains(planted), "{planted} leaked");
    }
}
