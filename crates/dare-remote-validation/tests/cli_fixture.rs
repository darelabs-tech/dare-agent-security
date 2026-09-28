//! Regenerates the CLI's replay fixture from a real REMOTE-LAB run:
//! `cargo test -p dare-remote-validation --test cli_fixture -- --ignored`.
//! The fixture holds no secret: the capture is scrubbed and the
//! authorization names only the credential's variable.

mod common;
mod lab;

use common::sim::{real, sources, Answers};
use common::*;
use dare_remote_validation::gateway::TrustRoots;
use dare_remote_validation::runner::run_remote;
use lab::{LabCa, LabServer};
use serde_json::json;
use time::OffsetDateTime;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes the committed CLI fixture"]
async fn regenerate_cli_replay_fixture() {
    let mut answers = Answers::default();
    answers.multi_turn("multiturn-lab-002");
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, answers.handler()).await;
    let (auth, plan) = real(
        &server.origin,
        "DARE_CONVERSATION",
        &["DARE_CONVERSATION_TURN"],
        &[("MULTI_TURN", "multiturn-lab-002", None)],
        json!({}),
        true,
    );
    std::env::set_var(TOKEN_ENV, TOKEN);
    let work = tempfile::tempdir().unwrap();
    let run = run_remote(
        &auth,
        &plan,
        &plan.origin,
        None,
        OffsetDateTime::now_utc(),
        TrustRoots::LabRoot(ca.root.to_vec()),
        tokio::runtime::Handle::current(),
        &sources(),
        work.path(),
    )
    .unwrap();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../dare-agent-security-cli/tests/fixtures/remote-replay");
    std::fs::create_dir_all(&dir).unwrap();
    let pretty = |v: serde_json::Value| {
        let mut b = serde_json::to_vec_pretty(&v).unwrap();
        b.push(b'\n');
        b
    };
    std::fs::write(
        dir.join("authorization.json"),
        pretty(serde_json::to_value(&auth).unwrap()),
    )
    .unwrap();
    std::fs::write(
        dir.join("plan.json"),
        pretty(serde_json::to_value(&plan).unwrap()),
    )
    .unwrap();
    for artifact in run.artifacts().unwrap() {
        let name = match artifact.name {
            "remote-capture.json" => "capture.json",
            "remote-audit.json" => "audit.json",
            "remote-result.json" => "expected-result.json",
            _ => continue,
        };
        assert!(!String::from_utf8_lossy(&artifact.bytes).contains(TOKEN));
        std::fs::write(dir.join(name), &artifact.bytes).unwrap();
    }
}
