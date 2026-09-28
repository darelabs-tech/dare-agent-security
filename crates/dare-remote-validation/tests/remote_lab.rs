//! REMOTE-LAB corpus (BLUEPRINT §7.2): every entry runs end to end through
//! `run_remote` (or `run_with_gateway` where DNS is injected) against an
//! in-process HTTPS target, and every non-refusal entry's replay is
//! byte-identical to its live result (O-03).

mod common;
mod lab;

use std::path::Path;
use std::sync::Arc;

use common::sim::{real, sources, Answers};
use common::*;
use dare_adversarial::KillTrigger;
use dare_remote_validation::address::NetworkScope;
use dare_remote_validation::authorization::{verify, Authorization};
use dare_remote_validation::gateway::{EgressGateway, TrustRoots};
use dare_remote_validation::outcome::{StopReason, TransportOutcome};
use dare_remote_validation::plan::RemotePlan;
use dare_remote_validation::resolver::PinnedResolver;
use dare_remote_validation::runner::{
    replay_capture, run_remote, run_with_gateway, EngineDigests, RemoteRun,
};
use dare_remote_validation::RemoteError;
use dare_security_evidence::Verdict;
use lab::{always, Handler, LabCa, LabReply, LabServer};
use serde_json::{json, Value};
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    A2a,
    Mcp,
    Egress,
    Transport,
    Credential,
    Refusal,
}

/// (id, class, what it stages)
const CORPUS: [(&str, Class, &str); 36] = [
    (
        "REMOTE-LAB-001",
        Class::A2a,
        "card from an unexpected provider",
    ),
    (
        "REMOTE-LAB-002",
        Class::A2a,
        "card from the expected provider (twin of 001)",
    ),
    (
        "REMOTE-LAB-003",
        Class::A2a,
        "multi-turn over A2A leaking across conversations",
    ),
    (
        "REMOTE-LAB-004",
        Class::A2a,
        "multi-turn over A2A, isolated (twin of 003)",
    ),
    (
        "REMOTE-LAB-005",
        Class::A2a,
        "card declaring an unknown transport",
    ),
    ("REMOTE-LAB-006", Class::A2a, "no Agent Card"),
    (
        "REMOTE-LAB-007",
        Class::A2a,
        "agent answering a JSON-RPC error",
    ),
    (
        "REMOTE-LAB-008",
        Class::A2a,
        "multi-turn over A2A with an eroding refusal",
    ),
    (
        "REMOTE-LAB-009",
        Class::Mcp,
        "metadata for another resource",
    ),
    (
        "REMOTE-LAB-010",
        Class::Mcp,
        "metadata for this resource (twin of 009)",
    ),
    (
        "REMOTE-LAB-011",
        Class::Mcp,
        "issuer not advertised by the resource",
    ),
    (
        "REMOTE-LAB-012",
        Class::Mcp,
        "issuer advertised by the resource (twin of 011)",
    ),
    (
        "REMOTE-LAB-013",
        Class::Mcp,
        "no protected-resource metadata",
    ),
    (
        "REMOTE-LAB-014",
        Class::Mcp,
        "authorization server on another origin",
    ),
    ("REMOTE-LAB-015", Class::Mcp, "oversize metadata"),
    (
        "REMOTE-LAB-016",
        Class::Mcp,
        "metadata behind an authentication challenge",
    ),
    ("REMOTE-LAB-017", Class::Egress, "redirect off origin"),
    (
        "REMOTE-LAB-018",
        Class::Egress,
        "host resolving to a metadata address",
    ),
    (
        "REMOTE-LAB-019",
        Class::Egress,
        "host resolving to a mixed answer",
    ),
    (
        "REMOTE-LAB-020",
        Class::Egress,
        "certificate for another name",
    ),
    (
        "REMOTE-LAB-021",
        Class::Egress,
        "answer that changes after the first lookup",
    ),
    (
        "REMOTE-LAB-022",
        Class::Egress,
        "host resolving to an IPv4-mapped private address",
    ),
    ("REMOTE-LAB-023", Class::Transport, "server error"),
    ("REMOTE-LAB-024", Class::Transport, "rate limited"),
    ("REMOTE-LAB-025", Class::Transport, "closed port"),
    ("REMOTE-LAB-026", Class::Transport, "oversize reply"),
    (
        "REMOTE-LAB-027",
        Class::Transport,
        "reply that is not the contract",
    ),
    (
        "REMOTE-LAB-028",
        Class::Credential,
        "credential echoed verbatim",
    ),
    (
        "REMOTE-LAB-029",
        Class::Credential,
        "credential echoed base64-encoded",
    ),
    (
        "REMOTE-LAB-030",
        Class::Credential,
        "credential-shaped strings in replies",
    ),
    (
        "REMOTE-LAB-031",
        Class::Refusal,
        "unsupported schema version",
    ),
    ("REMOTE-LAB-032", Class::Refusal, "window already closed"),
    (
        "REMOTE-LAB-033",
        Class::Refusal,
        "scenario digest not granted",
    ),
    (
        "REMOTE-LAB-034",
        Class::Refusal,
        "confirmation for another origin",
    ),
    (
        "REMOTE-LAB-035",
        Class::Refusal,
        "credential variable not set",
    ),
    (
        "REMOTE-LAB-036",
        Class::Refusal,
        "A2A policy outside --policy-dir",
    ),
];

#[test]
fn the_corpus_meets_its_class_contract() {
    assert!(CORPUS.len() >= 30);
    for (i, (id, _, _)) in CORPUS.iter().enumerate() {
        assert_eq!(
            *id,
            format!("REMOTE-LAB-{:03}", i + 1),
            "ids are contiguous"
        );
        let test_name = format!("fn remote_lab_{:03}_", i + 1);
        assert!(
            include_str!("remote_lab.rs").contains(&test_name),
            "{id} has a test"
        );
    }
    let count = |c: Class| CORPUS.iter().filter(|(_, k, _)| *k == c).count();
    assert!(count(Class::A2a) >= 8 && count(Class::Mcp) >= 8);
    assert!(count(Class::Egress) >= 6 && count(Class::Transport) >= 5);
    assert!(count(Class::Credential) >= 3 && count(Class::Refusal) >= 6);
}

const TURN: &str = "DARE_CONVERSATION_TURN";
const A2A: [&str; 3] = ["A2A_AGENT_CARD_GET", "A2A_MESSAGE_SEND", "A2A_TASKS_GET"];
const MCP: [&str; 2] = [
    "MCP_PROTECTED_RESOURCE_METADATA_GET",
    "MCP_AUTH_SERVER_METADATA_GET",
];

struct Lab {
    ca: LabCa,
    server: LabServer,
    work: tempfile::TempDir,
    policy: tempfile::TempDir,
}

async fn lab(handler: Handler) -> Lab {
    let ca = LabCa::generate();
    let server = LabServer::start(&ca, handler).await;
    Lab {
        ca,
        server,
        work: tempfile::tempdir().unwrap(),
        policy: tempfile::tempdir().unwrap(),
    }
}

impl Lab {
    fn run(&self, auth: &Authorization, plan: &RemotePlan) -> Result<RemoteRun, RemoteError> {
        std::env::set_var(TOKEN_ENV, TOKEN);
        let policy = plan
            .runs
            .iter()
            .any(|r| r.a2a_policy_file.is_some())
            .then(|| self.policy.path());
        run_remote(
            auth,
            plan,
            &plan.origin,
            policy,
            OffsetDateTime::now_utc(),
            TrustRoots::LabRoot(self.ca.root.to_vec()),
            tokio::runtime::Handle::current(),
            &sources(),
            self.work.path(),
        )
    }

    /// Run, check replay equivalence and artifact hygiene, return the run.
    fn decided(&self, auth: &Authorization, plan: &RemotePlan) -> RemoteRun {
        let live = self.run(auth, plan).expect("the run is admitted");
        let policy = plan
            .runs
            .iter()
            .any(|r| r.a2a_policy_file.is_some())
            .then(|| self.policy.path());
        let replay = replay_capture(
            auth,
            plan,
            &live.capture,
            &live.audit,
            policy,
            &sources(),
            self.work.path(),
        )
        .expect("replay");
        assert_eq!(
            serde_json::to_vec(&live.result).unwrap(),
            serde_json::to_vec(&replay.result).unwrap(),
            "O-03"
        );
        for artifact in live.artifacts().unwrap() {
            assert!(
                !String::from_utf8_lossy(&artifact.bytes).contains(TOKEN),
                "{}",
                artifact.name
            );
        }
        assert!(live
            .evidence
            .iter()
            .all(|e| dare_security_evidence::validate(e).is_ok()));
        live
    }

    fn a2a_policy(&self, provider: &str) {
        let peer = format!(
            "peer-{}",
            dare_remote_validation::canonical::short_hex(self.server.origin.as_bytes(), 16)
        );
        std::fs::write(self.policy.path().join("lab-policy.json"), serde_json::to_vec(&json!({
            "schema_version": "1", "policy_id": "lab-policy",
            "approved_peers": [{"peer_id": peer, "expected_provider": provider, "approved_scheme_kinds": ["HTTP_BEARER"]}]
        })).unwrap()).unwrap();
    }
}

// ---------- A2A ----------

fn agent(card: Value) -> Handler {
    Arc::new(move |hit| match (hit.method.as_str(), hit.path.as_str()) {
        ("GET", "/.well-known/agent-card.json") => LabReply::json(200, card.clone()),
        ("POST", "/a2a/v1") => {
            let request: Value = serde_json::from_slice(&hit.body).unwrap_or_default();
            LabReply::json(
                200,
                json!({"jsonrpc": "2.0", "id": request["id"], "result": {"role": "agent", "messageId": "r1",
                "contextId": request["params"]["message"]["contextId"], "parts": [{"kind": "text", "text": "I can summarize documents."}]}}),
            )
        }
        _ => LabReply::status(404),
    })
}

fn card(provider: &str) -> Value {
    json!({"name": "lab-agent", "protocolVersion": "0.3.0", "provider": {"organization": provider}, "url": "https://127.0.0.1/a2a/v1",
        "preferredTransport": "JSONRPC", "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}, "skills": [{"id": "summarize", "name": "Summarize"}]})
}

async fn a2a_card_case(served: Value, expected_provider: &str) -> RemoteRun {
    let lab = lab(agent(served)).await;
    lab.a2a_policy(expected_provider);
    let (auth, plan) = real(
        &lab.server.origin,
        "A2A",
        &A2A,
        &[("A2A", "A2A-LAB-001", Some("lab-policy.json"))],
        json!({}),
        true,
    );
    lab.decided(&auth, &plan)
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_001_card_from_an_unexpected_provider_fails() {
    assert_eq!(
        a2a_card_case(card("Attacker Inc"), "DARE Lab")
            .await
            .result
            .verdict,
        Verdict::Fail
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_002_card_from_the_expected_provider_never_fails() {
    let run = a2a_card_case(card("DARE Lab"), "DARE Lab").await;
    assert!(
        matches!(run.result.verdict, Verdict::Pass | Verdict::Inconclusive),
        "{:?}",
        run.result.verdict
    );
}

async fn a2a_multi_turn(id: &str) -> (Verdict, RemoteRun) {
    let mut answers = Answers::default();
    let offline = answers.multi_turn(id);
    let lab = lab(answers.a2a_handler()).await;
    let (auth, plan) = real(
        &lab.server.origin,
        "A2A",
        &A2A[..2],
        &[("MULTI_TURN", id, None)],
        json!({}),
        true,
    );
    (offline, lab.decided(&auth, &plan))
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_003_a_leak_across_conversations_fails_over_a2a() {
    let (offline, run) = a2a_multi_turn("multiturn-lab-035").await;
    assert_eq!(offline, Verdict::Fail);
    assert_eq!(
        run.result.verdict,
        Verdict::Fail,
        "the leak is visible in the text"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_004_the_isolated_twin_never_fails_and_never_passes_over_a2a() {
    let (offline, run) = a2a_multi_turn("multiturn-lab-034").await;
    assert_eq!(offline, Verdict::Pass);
    assert_eq!(
        run.result.verdict,
        Verdict::Inconclusive,
        "A2A cannot show the invariant held"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_005_an_unknown_transport_is_never_a_pass() {
    let mut served = card("DARE Lab");
    served["preferredTransport"] = "SOAP".into();
    let run = a2a_card_case(served, "DARE Lab").await;
    assert_ne!(run.result.verdict, Verdict::Pass);
    assert_eq!(
        run.result.runs[0].transport,
        Some(TransportOutcome::ProtocolViolation)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_006_no_agent_card_is_never_a_pass() {
    let lab = lab(always(LabReply::status(404))).await;
    lab.a2a_policy("DARE Lab");
    let (auth, plan) = real(
        &lab.server.origin,
        "A2A",
        &A2A,
        &[("A2A", "A2A-LAB-001", Some("lab-policy.json"))],
        json!({}),
        false,
    );
    let run = lab.decided(&auth, &plan);
    assert_ne!(run.result.verdict, Verdict::Pass);
    assert_eq!(
        run.result.runs[0].transport,
        Some(TransportOutcome::NotFound)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_007_a_jsonrpc_error_is_never_a_pass() {
    let served = card("DARE Lab");
    let handler: Handler = Arc::new(move |hit| match hit.path.as_str() {
        "/.well-known/agent-card.json" => LabReply::json(200, served.clone()),
        _ => {
            let request: Value = serde_json::from_slice(&hit.body).unwrap_or_default();
            LabReply::json(
                200,
                json!({"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32001, "message": "denied"}}),
            )
        }
    });
    let lab = lab(handler).await;
    lab.a2a_policy("DARE Lab");
    let (auth, plan) = real(
        &lab.server.origin,
        "A2A",
        &A2A,
        &[("A2A", "A2A-LAB-001", Some("lab-policy.json"))],
        json!({}),
        true,
    );
    assert_ne!(lab.decided(&auth, &plan).result.verdict, Verdict::Pass);
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_008_an_eroding_refusal_over_a2a_is_never_a_pass() {
    let (offline, run) = a2a_multi_turn("multiturn-lab-008").await;
    assert_eq!(offline, Verdict::Fail);
    assert_ne!(
        run.result.verdict,
        Verdict::Pass,
        "fields A2A cannot carry must not read as a refusal"
    );
}

// ---------- MCP ----------

fn mcp(
    resource_suffix: &'static str,
    issuer_suffix: &'static str,
    as_origin: Option<&'static str>,
) -> (Handler, Arc<std::sync::Mutex<u16>>) {
    let port = Arc::new(std::sync::Mutex::new(0u16));
    let cell = port.clone();
    let handler: Handler = Arc::new(move |hit| {
        let origin = format!("https://127.0.0.1:{}", *cell.lock().unwrap());
        let server = as_origin
            .map(str::to_owned)
            .unwrap_or_else(|| origin.clone());
        match hit.path.as_str() {
            "/.well-known/oauth-protected-resource" => LabReply::json(
                200,
                json!({"resource": format!("{origin}{resource_suffix}"), "authorization_servers": [server]}),
            ),
            "/.well-known/oauth-authorization-server" => LabReply::json(
                200,
                json!({"issuer": format!("{origin}{issuer_suffix}"), "code_challenge_methods_supported": ["S256"]}),
            ),
            _ => LabReply::status(404),
        }
    });
    (handler, port)
}

async fn mcp_case(
    handler: Handler,
    port: Option<Arc<std::sync::Mutex<u16>>>,
    id: &str,
) -> (RemoteRun, Lab) {
    let lab = lab(handler).await;
    if let Some(port) = port {
        *port.lock().unwrap() = lab.server.addr.port();
    }
    let (auth, plan) = real(
        &lab.server.origin,
        "MCP",
        &MCP,
        &[("MCP_AUTH", id, None)],
        json!({}),
        true,
    );
    (lab.decided(&auth, &plan), lab)
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_009_metadata_for_another_resource_fails() {
    let (h, p) = mcp("/elsewhere", "", None);
    assert_eq!(
        mcp_case(h, Some(p), "MCP-AUTH-LAB-005")
            .await
            .0
            .result
            .verdict,
        Verdict::Fail
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_010_metadata_for_this_resource_never_fails() {
    let (h, p) = mcp("/mcp", "", None);
    assert!(matches!(
        mcp_case(h, Some(p), "MCP-AUTH-LAB-005")
            .await
            .0
            .result
            .verdict,
        Verdict::Pass | Verdict::Inconclusive
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_011_an_unadvertised_issuer_fails() {
    let (h, p) = mcp("/mcp", "/rogue", None);
    assert_eq!(
        mcp_case(h, Some(p), "MCP-AUTH-LAB-007")
            .await
            .0
            .result
            .verdict,
        Verdict::Fail
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_012_an_advertised_issuer_never_fails() {
    let (h, p) = mcp("/mcp", "", None);
    assert!(matches!(
        mcp_case(h, Some(p), "MCP-AUTH-LAB-007")
            .await
            .0
            .result
            .verdict,
        Verdict::Pass | Verdict::Inconclusive
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_013_missing_metadata_is_never_a_pass() {
    let (run, lab) = mcp_case(always(LabReply::status(404)), None, "MCP-AUTH-LAB-005").await;
    assert_ne!(run.result.verdict, Verdict::Pass);
    assert_eq!(lab.server.hits().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_014_an_off_origin_authorization_server_is_never_fetched() {
    let (h, p) = mcp("/mcp", "", Some("https://as.example.test"));
    let (run, lab) = mcp_case(h, Some(p), "MCP-AUTH-LAB-007").await;
    assert_eq!(
        lab.server.hits().len(),
        1,
        "only the protected-resource metadata"
    );
    assert_ne!(run.result.verdict, Verdict::Pass);
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_015_oversize_metadata_is_never_a_pass() {
    let big = LabReply {
        body: vec![b' '; 2_000_000],
        ..LabReply::json(200, json!({}))
    };
    let (run, _) = mcp_case(always(big), None, "MCP-AUTH-LAB-005").await;
    assert_ne!(run.result.verdict, Verdict::Pass);
    assert_eq!(
        run.result.runs[0].transport,
        Some(TransportOutcome::Oversize)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_016_a_challenge_on_metadata_is_observed_not_killed() {
    let (run, _) = mcp_case(
        always(
            LabReply::status(401).with_header("www-authenticate", "Bearer resource_metadata=\"x\""),
        ),
        None,
        "MCP-AUTH-LAB-005",
    )
    .await;
    assert_ne!(run.result.verdict, Verdict::Pass);
    assert_ne!(
        run.capture.stop_reason,
        StopReason::KillSwitch,
        "a challenge on metadata is the observation"
    );
    assert!(run.capture.entries[0].www_authenticate.is_some());
}

// ---------- egress hostility ----------

async fn conversation_lab(handler: Handler) -> (Lab, Authorization, RemotePlan) {
    let lab = lab(handler).await;
    let (auth, plan) = real(
        &lab.server.origin,
        "DARE_CONVERSATION",
        &[TURN],
        &[("MULTI_TURN", "multiturn-lab-001", None)],
        json!({}),
        true,
    );
    (lab, auth, plan)
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_017_a_redirect_off_origin_kills_and_reaches_nothing() {
    let ca = LabCa::generate();
    let elsewhere = LabServer::start(&ca, always(LabReply::status(200))).await;
    let location = format!("{}/stolen", elsewhere.origin);
    let (lab, auth, plan) = conversation_lab(always(
        LabReply::status(302).with_header("location", &location),
    ))
    .await;
    let _ = ca;
    let run = lab.decided(&auth, &plan);
    assert_eq!(run.capture.stop_reason, StopReason::KillSwitch);
    assert!(run
        .audit
        .events
        .iter()
        .any(|e| e.detail.as_deref() == Some("UNEXPECTED_TARGET")));
    assert!(elsewhere.hits().is_empty());
    assert_ne!(run.result.verdict, Verdict::Pass);
}

/// A hostname origin whose lookups are injected. Returns the error or run.
async fn resolved(
    answer: fn(u32) -> Vec<std::net::IpAddr>,
) -> (Result<RemoteRun, RemoteError>, Lab) {
    let mut answers = Answers::default();
    answers.multi_turn("multiturn-lab-001");
    let lab = lab(answers.handler()).await;
    let origin = format!("https://localhost:{}", lab.server.addr.port());
    let (auth, plan) = real(
        &origin,
        "DARE_CONVERSATION",
        &[TURN],
        &[("MULTI_TURN", "multiturn-lab-001", None)],
        json!({}),
        true,
    );
    std::env::set_var(TOKEN_ENV, TOKEN);
    let mut verified = verify(
        &auth,
        &plan,
        &origin,
        OffsetDateTime::now_utc(),
        &EngineDigests {
            sources: &sources(),
        },
        &|n| std::env::var(n).ok(),
    )
    .unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let resolver = PinnedResolver::with_lookup("localhost", NetworkScope::LoopbackLab, move |_| {
        answer(calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
    });
    let gateway = EgressGateway::with_test_resolver(
        &mut verified,
        &plan,
        &origin,
        TrustRoots::LabRoot(lab.ca.root.to_vec()),
        resolver,
    )
    .unwrap();
    let run = run_with_gateway(
        &auth,
        &plan,
        None,
        gateway,
        tokio::runtime::Handle::current(),
        &sources(),
        lab.work.path(),
    );
    (run, lab)
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_018_a_metadata_address_is_refused_before_connecting() {
    let (run, lab) = resolved(|_| vec!["169.254.169.254".parse().unwrap()]).await;
    let run = run.expect("reported through the result");
    assert!(lab.server.hits().is_empty());
    assert_eq!(run.capture.stop_reason, StopReason::TransportError);
    assert!(run
        .audit
        .events
        .iter()
        .any(|e| e.detail.as_deref() == Some("ADDRESS_NOT_PERMITTED")));
    assert_ne!(run.result.verdict, Verdict::Pass);
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_019_a_mixed_answer_is_refused_before_connecting() {
    let (run, lab) =
        resolved(|_| vec!["127.0.0.1".parse().unwrap(), "10.0.0.9".parse().unwrap()]).await;
    assert!(lab.server.hits().is_empty());
    assert_ne!(run.unwrap().result.verdict, Verdict::Pass);
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_020_a_certificate_for_another_name_is_an_error() {
    let ca = LabCa::generate();
    let server =
        LabServer::start_with_names(&ca, &["wrong.example.test"], always(LabReply::status(200)))
            .await;
    let lab = Lab {
        ca,
        server,
        work: tempfile::tempdir().unwrap(),
        policy: tempfile::tempdir().unwrap(),
    };
    let (auth, plan) = real(
        &lab.server.origin,
        "DARE_CONVERSATION",
        &[TURN],
        &[("MULTI_TURN", "multiturn-lab-001", None)],
        json!({}),
        true,
    );
    let run = lab.decided(&auth, &plan);
    assert_eq!(run.result.runs[0].transport, Some(TransportOutcome::Tls));
    assert_eq!(run.result.verdict, Verdict::Error);
    assert!(lab.server.hits().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_021_a_changing_answer_is_never_followed() {
    let (run, lab) = resolved(|call| {
        if call == 0 {
            vec!["127.0.0.1".parse().unwrap()]
        } else {
            vec!["10.0.0.9".parse().unwrap()]
        }
    })
    .await;
    let run = run.unwrap();
    assert_eq!(run.capture.pinned_addresses, vec!["127.0.0.1".to_owned()]);
    assert_eq!(
        run.result.verdict,
        Verdict::Pass,
        "the pinned loopback target answered every turn"
    );
    assert!(!lab.server.hits().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_022_an_ipv4_mapped_private_address_is_refused() {
    let (run, lab) = resolved(|_| vec!["::ffff:192.168.1.10".parse().unwrap()]).await;
    assert!(lab.server.hits().is_empty());
    assert_ne!(run.unwrap().result.verdict, Verdict::Pass);
}

// ---------- transport faults ----------

async fn fault(reply: LabReply) -> RemoteRun {
    let (lab, auth, plan) = conversation_lab(always(reply)).await;
    lab.decided(&auth, &plan)
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_023_a_server_error_is_never_a_pass() {
    let run = fault(LabReply::status(503)).await;
    assert_ne!(run.result.verdict, Verdict::Pass);
    assert_eq!(
        run.result.runs[0].transport,
        Some(TransportOutcome::ServerError)
    );
    assert_eq!(
        run.capture.stop_reason,
        StopReason::KillSwitch,
        "instability on the first failure"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_024_rate_limiting_is_never_a_pass() {
    let run = fault(LabReply::status(429)).await;
    assert_ne!(run.result.verdict, Verdict::Pass);
    assert_eq!(
        run.result.runs[0].transport,
        Some(TransportOutcome::RateLimited)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_025_a_closed_port_is_an_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    drop(listener);
    let lab = lab(always(LabReply::status(200))).await;
    let (auth, plan) = real(
        &origin,
        "DARE_CONVERSATION",
        &[TURN],
        &[("MULTI_TURN", "multiturn-lab-001", None)],
        json!({}),
        true,
    );
    let run = lab.decided(&auth, &plan);
    assert_eq!(run.result.verdict, Verdict::Error);
    assert_eq!(
        run.result.runs[0].transport,
        Some(TransportOutcome::Connection)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_026_an_oversize_reply_is_never_a_pass() {
    let run = fault(LabReply {
        body: vec![b'x'; 1_100_000],
        ..LabReply::json(200, json!({}))
    })
    .await;
    assert_ne!(run.result.verdict, Verdict::Pass);
    assert_eq!(
        run.result.runs[0].transport,
        Some(TransportOutcome::Oversize)
    );
    assert!(run.capture.entries[0].response_body.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_027_a_reply_outside_the_contract_is_never_a_pass() {
    let run = fault(LabReply::json(
        200,
        json!({"verdict": "PASS", "note": "trust me"}),
    ))
    .await;
    assert_ne!(run.result.verdict, Verdict::Pass);
}

// ---------- credential hygiene ----------

fn assert_token_absent(run: &RemoteRun, needle: &str) {
    for artifact in run.artifacts().unwrap() {
        assert!(
            !String::from_utf8_lossy(&artifact.bytes).contains(needle),
            "{}",
            artifact.name
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_028_an_echoed_credential_kills_and_leaves_no_trace() {
    let echo: Handler = Arc::new(|hit| LabReply::json(200, json!({"seen": hit.authorization})));
    let (lab, auth, plan) = conversation_lab(echo).await;
    let run = lab.decided(&auth, &plan);
    assert!(run
        .audit
        .events
        .iter()
        .any(|e| e.detail.as_deref() == Some("SECRET_DETECTED")));
    assert_eq!(run.capture.stop_reason, StopReason::KillSwitch);
    assert_eq!(lab.server.hits().len(), 1, "no request after the echo");
    assert_token_absent(&run, TOKEN);
    let display = format!("{}", RemoteError::Killed(KillTrigger::SecretDetected));
    assert!(!display.contains(TOKEN));
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_029_a_base64_echo_is_scrubbed_and_kills() {
    let echo: Handler = Arc::new(|_| LabReply::json(200, json!({"b64": b64(TOKEN.as_bytes())})));
    let (lab, auth, plan) = conversation_lab(echo).await;
    let run = lab.decided(&auth, &plan);
    assert_eq!(run.capture.stop_reason, StopReason::KillSwitch);
    assert_token_absent(&run, &b64(TOKEN.as_bytes()));
}

/// Standard base64 with padding.
fn b64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_030_credential_shapes_are_scrubbed_without_a_kill() {
    let shaped = ["gh", "p_", "0123456789abcdefghijABCDEFGH"].concat();
    let body = json!({"schema_version": "1", "conversation_id": "conv-a", "turn_index": 0, "output_text": format!("token {shaped}"),
        "refusal": true, "decision": "DENY", "fulfillment": "NO_FULFILLMENT", "accepted_authority": null, "actions": []});
    let run = fault(LabReply::json(200, body)).await;
    assert!(run.capture.entries[0].scrubbed_shapes >= 1);
    assert_token_absent(&run, &shaped);
    assert!(!run
        .audit
        .events
        .iter()
        .any(|e| e.detail.as_deref() == Some("SECRET_DETECTED")));
}

// ---------- authorization refusals ----------

async fn refused(
    mutate: impl FnOnce(&mut Authorization, &mut RemotePlan, &Path) -> Option<String>,
) {
    let lab = lab(always(LabReply::status(200))).await;
    let (mut auth, mut plan) = real(
        &lab.server.origin,
        "DARE_CONVERSATION",
        &[TURN],
        &[("MULTI_TURN", "multiturn-lab-001", None)],
        json!({}),
        true,
    );
    let confirm =
        mutate(&mut auth, &mut plan, lab.policy.path()).unwrap_or_else(|| plan.origin.clone());
    let policy = plan
        .runs
        .iter()
        .any(|r| r.a2a_policy_file.is_some())
        .then(|| lab.policy.path());
    let result = run_remote(
        &auth,
        &plan,
        &confirm,
        policy,
        OffsetDateTime::now_utc(),
        TrustRoots::LabRoot(lab.ca.root.to_vec()),
        tokio::runtime::Handle::current(),
        &sources(),
        lab.work.path(),
    );
    assert!(result.is_err(), "refused");
    assert!(lab.server.hits().is_empty(), "0 requests");
    assert_eq!(
        std::fs::read_dir(lab.work.path()).unwrap().count(),
        0,
        "nothing written"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_031_an_unsupported_version_is_refused() {
    refused(|a, _, _| {
        a.schema_version = "2".into();
        None
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_032_a_closed_window_is_refused() {
    refused(|a, p, _| {
        a.not_after = stamp(time::Duration::seconds(-1));
        p.authorization_digest = dare_remote_validation::canonical::digest(a).unwrap();
        None
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_033_an_ungranted_digest_is_refused() {
    refused(|_, p, _| {
        p.runs[0].scenario_digest = D2.into();
        None
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_034_a_confirmation_for_another_origin_is_refused() {
    refused(|_, _, _| Some("https://127.0.0.1:1".into())).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_035_a_missing_credential_is_refused() {
    refused(|a, p, _| {
        a.credential_ref = Some("DARE_REMOTE_LAB_UNSET_VARIABLE".into());
        p.authorization_digest = dare_remote_validation::canonical::digest(a).unwrap();
        None
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_lab_036_a_policy_outside_the_policy_dir_is_refused() {
    let lab = lab(always(LabReply::status(200))).await;
    let (auth, plan) = real(
        &lab.server.origin,
        "A2A",
        &A2A,
        &[("A2A", "A2A-LAB-001", Some("../escape-policy.json"))],
        json!({}),
        true,
    );
    std::env::set_var(TOKEN_ENV, TOKEN);
    let result = run_remote(
        &auth,
        &plan,
        &plan.origin,
        Some(lab.policy.path()),
        OffsetDateTime::now_utc(),
        TrustRoots::LabRoot(lab.ca.root.to_vec()),
        tokio::runtime::Handle::current(),
        &sources(),
        lab.work.path(),
    );
    assert!(
        matches!(
            result,
            Err(RemoteError::Refused(_))
                | Err(RemoteError::Schema { .. })
                | Err(RemoteError::Authorization(_))
        ),
        "{:?}",
        result.err()
    );
    assert!(lab.server.hits().is_empty());
}
