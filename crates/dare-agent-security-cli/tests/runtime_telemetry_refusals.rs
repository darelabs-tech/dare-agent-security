//! `validate runtime-telemetry` refusal corpus and double run (Cycle 025
//! task-023). Every refusal the CLI can reach exits 3, writes nothing and
//! echoes no planted value; two runs over the same inputs give the same bytes.
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::{json, Value};

/// Planted in every refused input; it must never reach stdout or stderr.
const CANARY: &str = "CANARY-REFUSAL-4c1d8e";

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dare-agent-security"))
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

fn export(spans: Vec<Value>) -> Value {
    json!({"resourceSpans": [{
        "resource": {"attributes": []},
        "scopeSpans": [{"scope": {"name": "refusals"}, "spans": spans}]
    }]})
}

fn good(t: &str) -> Value {
    export(vec![
        span(
            t,
            "a",
            None,
            10,
            &[
                ("gen_ai.operation.name", "invoke_agent"),
                ("gen_ai.agent.name", "assistant"),
                ("user.id", "user-7"),
            ],
        ),
        span(
            t,
            "b",
            Some("a"),
            20,
            &[
                ("gen_ai.operation.name", "execute_tool"),
                ("gen_ai.tool.name", "search"),
                ("user.id", "user-7"),
            ],
        ),
    ])
}

fn policy() -> Value {
    json!({
        "schema_version": "1", "policy_id": "support-desk", "content_capture_allowed": false,
        "principal_keys": ["user.id"], "tenant_keys": ["tenant.id"],
        "required_operations": ["TOOL_EXEC"],
        "agents": [{"name": "assistant", "allowed_tools": ["search"], "principal": "user-7"}]
    })
}

fn write_bytes(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

fn write(root: &Path, name: &str, value: &Value) -> PathBuf {
    write_bytes(root, name, &serde_json::to_vec(value).unwrap())
}

/// Valid JSON of exactly `len` bytes: the export padded with spaces.
fn padded(value: &Value, len: usize) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    assert!(bytes.len() <= len);
    bytes.resize(len, b' ');
    bytes
}

fn run(traces: &[&Path], policy: Option<&Path>, extra: &[&str], out: &Path) -> Output {
    let mut cmd = Command::new(bin());
    cmd.args(["validate", "runtime-telemetry"]);
    for t in traces {
        cmd.arg("--traces").arg(t);
    }
    if let Some(p) = policy {
        cmd.arg("--policy").arg(p);
    }
    cmd.arg("--output-dir").arg(out).args(extra);
    cmd.output().expect("binary runs")
}

/// Exit 3 for the expected reason, nothing written, no canary and no path
/// echoed.
fn assert_refused(label: &str, output: &Output, out: &Path, reason: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{label}: {stdout}{stderr}");
    assert!(!out.exists(), "{label}: wrote the output directory");
    for text in [&stdout, &stderr] {
        assert!(!text.contains(CANARY), "{label}: echoed the canary");
        assert!(
            !text.contains("/tmp") && !text.contains(".json"),
            "{label}: echoed a path: {text}"
        );
    }
    assert!(stderr.starts_with("refused: "), "{label}: {stderr}");
    assert!(
        stderr.contains(reason),
        "{label}: expected {reason:?}, got {stderr}"
    );
}

#[test]
fn every_trace_admission_refusal_exits_3_and_writes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    let good_path = write(r, "good.json", &good("1"));
    let out = r.join("out");

    // Unreadable: missing, and a directory.
    let missing = r.join(format!("{CANARY}-missing.json"));
    assert_refused(
        "missing",
        &run(&[&good_path, &missing], None, &[], &out),
        &out,
        "trace file 1 cannot be read",
    );
    let dir = r.join(format!("{CANARY}-dir"));
    fs::create_dir(&dir).unwrap();
    assert_refused(
        "directory",
        &run(&[&dir], None, &[], &out),
        &out,
        "trace file 0 cannot be read",
    );

    // A symbolic link, even to a valid file.
    let link = r.join("link.json");
    std::os::unix::fs::symlink(&good_path, &link).unwrap();
    assert_refused(
        "symlink",
        &run(&[&link], None, &[], &out),
        &out,
        "trace file 0 is a symbolic link",
    );

    // More files than the maximum (64).
    let many: Vec<PathBuf> = (0..65)
        .map(|i| write(r, &format!("many-{i}.json"), &good(&format!("{:x}", i + 1))))
        .collect();
    let refs: Vec<&Path> = many.iter().map(PathBuf::as_path).collect();
    assert_refused(
        "65 files",
        &run(&refs, None, &[], &out),
        &out,
        "more trace files than the maximum",
    );

    // One file over 16 MiB, at limit + 1.
    let big = write_bytes(r, "big.json", &padded(&good("1"), 16 * 1024 * 1024 + 1));
    assert_refused(
        "file size",
        &run(&[&big], None, &[], &out),
        &out,
        "trace file 0 exceeds its size limit",
    );

    // JSON nested 65 levels deep.
    let deep = format!("{}{}", "[".repeat(65), "]".repeat(65));
    let deep = write_bytes(r, "deep.json", deep.as_bytes());
    assert_refused(
        "depth",
        &run(&[&deep], None, &[], &out),
        &out,
        "deeper than 64 levels",
    );

    // Not UTF-8, and not JSON.
    let bytes = write_bytes(r, "bytes.json", &[0xff, 0xfe, 0x00]);
    assert_refused(
        "utf-8",
        &run(&[&bytes], None, &[], &out),
        &out,
        "trace file 0 is not valid OTLP/JSON",
    );
    let text = write_bytes(r, "text.json", format!("not json {CANARY}").as_bytes());
    assert_refused(
        "json",
        &run(&[&text], None, &[], &out),
        &out,
        "trace file 0 is not valid OTLP/JSON",
    );
}

#[test]
fn the_total_size_limit_is_enforced_across_files() {
    // 17 files of 15.5 MiB: each is under 16 MiB, together over 256 MiB.
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    let files: Vec<PathBuf> = (0..17)
        .map(|i| {
            write_bytes(
                r,
                &format!("part-{i}.json"),
                &padded(&good(&format!("{:x}", i + 1)), 31 * 512 * 1024),
            )
        })
        .collect();
    let refs: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
    let out = r.join("out");
    assert_refused(
        "total size",
        &run(&refs, None, &[], &out),
        &out,
        "exceed the total size limit",
    );
}

#[test]
fn every_trace_content_refusal_exits_3() {
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    let out = r.join("out");
    let cases: Vec<(&str, Value)> = vec![
        ("unknown top-level field", {
            let mut v = good("1");
            v["extra"] = json!(CANARY);
            v
        }),
        ("enum name for kind", {
            let mut v = good("1");
            v["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["kind"] = json!("SPAN_KIND_CLIENT");
            v
        }),
        ("short trace id", {
            let mut v = good("1");
            v["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["traceId"] = json!("abc");
            v
        }),
        ("all-zero span id", {
            let mut v = good("1");
            v["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["spanId"] =
                json!("0000000000000000");
            v
        }),
        ("non-hex id", {
            let mut v = good("1");
            v["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["spanId"] =
                json!(format!("{:z>16}", "g"));
            v
        }),
        ("non-numeric time", {
            let mut v = good("1");
            v["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["startTimeUnixNano"] = json!(CANARY);
            v
        }),
        (
            "resourceSpans not an array",
            json!({"resourceSpans": CANARY}),
        ),
    ];
    let good_path = write(r, "good.json", &good("2"));
    for (label, value) in cases {
        let bad = write(r, "bad.json", &value);
        let output = run(&[&good_path, &bad], None, &[], &out);
        // Refusals name the position, never the content.
        assert_refused(label, &output, &out, "trace file 1 is not valid OTLP/JSON");
    }
}

#[test]
fn every_policy_refusal_exits_3() {
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    let t = write(r, "t.json", &good("1"));
    let out = r.join("out");
    let mut cases: Vec<(&str, PathBuf, &str)> = Vec::new();
    let mut variant = |label: &'static str, reason: &'static str, f: &dyn Fn(&mut Value)| {
        let mut p = policy();
        f(&mut p);
        let path = write(r, &format!("policy-{}.json", cases.len()), &p);
        cases.push((label, path, reason));
    };
    variant("missing field", "(schema)", &|p| {
        p.as_object_mut().unwrap().remove("agents");
    });
    variant("unknown field", "(schema)", &|p| p["extra"] = json!(CANARY));
    variant("bad schema version", "(schema", &|p| {
        p["schema_version"] = json!("2")
    });
    variant("bad policy id", "(schema)", &|p| {
        p["policy_id"] = json!(format!("A {CANARY}"))
    });
    // Well-formed, but not on the closed principal-key allow-list (AD-09).
    variant("key off the allow-list", "(principal_key)", &|p| {
        p["principal_keys"] = json!(["x.custom.principal"])
    });
    variant("unknown operation", "(schema)", &|p| {
        p["required_operations"] = json!([CANARY])
    });
    cases.push((
        "policy over 1 MiB",
        write_bytes(r, "big-policy.json", &padded(&policy(), 1024 * 1024 + 1)),
        "the policy file exceeds its size limit",
    ));
    cases.push((
        "policy not JSON",
        write_bytes(r, "text-policy.json", CANARY.as_bytes()),
        "the policy file",
    ));
    let link = r.join("policy-link.json");
    std::os::unix::fs::symlink(write(r, "real-policy.json", &policy()), &link).unwrap();
    cases.push(("policy symlink", link, "the policy file is a symbolic link"));
    for (label, p, reason) in &cases {
        let output = run(&[&t], Some(p), &[], &out);
        assert_refused(label, &output, &out, reason);
    }
}

#[test]
fn bound_and_output_directory_refusals_exit_3() {
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    let t = write(r, "t.json", &good("1"));
    let out = r.join("out");
    for bound in ["0", "1000001"] {
        let output = run(&[&t], None, &["--max-spans", bound], &out);
        let reason = if bound == "0" {
            "max_spans must be at least 1"
        } else {
            "max_spans is above its maximum"
        };
        assert_refused(&format!("max-spans {bound}"), &output, &out, reason);
    }
    // Parent traversal in the output directory.
    let traversal = r.join("a/../out");
    let output = run(&[&t], None, &[], &traversal);
    assert_eq!(output.status.code(), Some(3));
    assert!(!out.exists());
}

#[test]
fn an_artifact_that_fails_the_output_sweep_is_never_written() {
    // A policy id the schema admits but that looks like a live key: the result
    // would carry it, so the sweep refuses before the first write.
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    let t = write(r, "t.json", &good("1"));
    let mut p = policy();
    p["policy_id"] = json!("sk-live-policy-4c1d8e");
    let p = write(r, "p.json", &p);
    let out = r.join("out");
    let output = run(&[&t], Some(&p), &[], &out);
    assert_eq!(output.status.code(), Some(3));
    assert!(!out.exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("runtime-telemetry-result.json"), "{stderr}");
    assert!(!stderr.contains("sk-live"));
}

#[test]
fn two_runs_give_byte_identical_files_whatever_the_file_order() {
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    let a = write(r, "a.json", &good("1"));
    let mut bad = good("2");
    bad["resourceSpans"][0]["scopeSpans"][0]["spans"][1]["attributes"][1]["value"]["stringValue"] =
        json!("delete_all");
    let b = write(r, "b.json", &bad);
    let p = write(r, "p.json", &policy());
    let first = r.join("first");
    let second = r.join("second");
    assert_eq!(run(&[&a, &b], Some(&p), &[], &first).status.code(), Some(2));
    assert_eq!(
        run(&[&b, &a], Some(&p), &[], &second).status.code(),
        Some(2)
    );
    let mut names: Vec<_> = fs::read_dir(&first)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(names.len(), 4);
    for name in names {
        assert_eq!(
            fs::read(first.join(&name)).unwrap(),
            fs::read(second.join(&name)).unwrap(),
            "{name:?} differs"
        );
    }
}
