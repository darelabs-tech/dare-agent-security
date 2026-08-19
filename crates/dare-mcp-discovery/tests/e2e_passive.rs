//! Cycle 002 E2E: discovery stays inside the passive allowlist.
//!
//! Lab method traces are the source of truth for `set(methods) ⊆ Cycle002Allowlist`.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

use dare_mcp_discovery::{
    emit_baseline_evidence, enumerate_inventory, validate, validate_instance, AuthMechanism,
    AuthSnapshot, AuthState, CapabilitySnapshot, Completeness, DiscoveryClient, DiscoveryInventory,
    DiscoveryObservation, DiscoveryTarget, DiscoveryTargetSpec, DiscoveryTimeouts,
    EnumerationBounds, EnumerationContext, EnumerationOutcome, McpDiscoveryClient, PolicyProfile,
    ProtocolSnapshot, ScannerMetadata, TransportKind, TransportSnapshot, WarningCode,
    CURRENT_WIRE_REVISION, LEGACY_WIRE_REVISION,
};
use synthetic_mcp::{
    serve_loopback_http, MethodTrace, SyntheticMcpLab, EXTERNAL_SCHEMA_REF, PROMPT_NAMES,
    RESOURCE_URIS, TOOL_NAMES, TOOL_PAGE_SIZE,
};
use time::OffsetDateTime;

const FORBIDDEN: &[&str] = &["tools/call", "resources/read", "prompts/get", "ping"];
const CANARY: &str = "sk_live_PLANTED_SECRET_VALUE_9f3a";

fn assert_passive_trace(methods: &[String], profile: PolicyProfile) {
    let allow = profile.allowlisted_methods();
    for method in methods {
        assert!(
            allow.contains(&method.as_str()),
            "lab received {method} which is outside Cycle002Allowlist {allow:?}; trace={methods:?}"
        );
        assert!(
            !FORBIDDEN.contains(&method.as_str()),
            "forbidden method reached the lab: {method}; trace={methods:?}"
        );
        assert!(!method.contains(CANARY));
    }
}

fn assert_catalog(inventory: &DiscoveryInventory, expect_all_tools: bool) {
    validate(inventory).expect("inventory must validate");
    let value = serde_json::to_value(inventory).expect("json");
    validate_instance(&value).expect("schema");
    assert!(!format!("{value}").contains(CANARY));

    let tools: BTreeSet<_> = inventory
        .tools
        .iter()
        .map(|tool| tool.name.as_str())
        .collect();
    if expect_all_tools {
        for name in TOOL_NAMES {
            assert!(tools.contains(name), "missing tool {name}");
        }
    } else {
        assert_eq!(tools.len(), TOOL_PAGE_SIZE);
    }

    let resources: BTreeSet<_> = inventory
        .resources
        .iter()
        .map(|resource| resource.uri.as_str())
        .collect();
    for uri in RESOURCE_URIS {
        assert!(resources.contains(uri), "missing resource {uri}");
        assert!(
            uri.starts_with("synthetic://"),
            "discovered URI must stay synthetic"
        );
    }

    let prompts: BTreeSet<_> = inventory
        .prompts
        .iter()
        .map(|prompt| prompt.name.as_str())
        .collect();
    for name in PROMPT_NAMES {
        assert!(prompts.contains(name), "missing prompt {name}");
    }

    let ambiguous = inventory
        .tools
        .iter()
        .find(|tool| tool.name == "legacy.ambiguous");
    if let Some(tool) = ambiguous {
        let encoded = serde_json::to_string(&tool.input_schema).expect("schema");
        assert!(
            encoded.contains(EXTERNAL_SCHEMA_REF),
            "external $ref must be retained without fetching"
        );
    }
}

fn envelope(
    profile: PolicyProfile,
    revision: &str,
    transport: TransportSnapshot,
) -> EnumerationContext {
    EnumerationContext {
        target: DiscoveryTarget {
            id: "synthetic-rental-mcp".to_owned(),
            display_name: None,
            endpoint_fingerprint: Some("127.0.0.1".to_owned()),
        },
        protocol: ProtocolSnapshot {
            revision: revision.to_owned(),
            negotiated: true,
            client_name: Some("dare-mcp-discovery".to_owned()),
            client_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        },
        transport,
        server: None,
        capabilities: CapabilitySnapshot {
            tools: true,
            resources: true,
            resource_templates: true,
            prompts: true,
        },
        auth: AuthSnapshot {
            state: AuthState::NotApplicable,
            mechanism: AuthMechanism::NoneObserved,
        },
        generated_at: OffsetDateTime::now_utc(),
        scanner: Some(ScannerMetadata {
            name: "dare-mcp-discovery".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }),
        policy_profile: profile,
    }
}

fn bounds_with_pages(max_pages: usize) -> EnumerationBounds {
    let mut bounds = EnumerationBounds::new();
    bounds.max_pages_per_collection = max_pages;
    bounds.request_timeout = Duration::from_secs(5);
    bounds.overall_timeout = Duration::from_secs(15);
    bounds
}

async fn enumerate_http(
    profile: PolicyProfile,
    max_pages: usize,
) -> (
    EnumerationOutcome,
    Vec<String>,
    Vec<String>,
    synthetic_mcp::LoopbackHttpServer,
) {
    let trace = MethodTrace::new();
    let lab = SyntheticMcpLab::with_trace(trace.clone());
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("bind");
    let server = serve_loopback_http(bind, lab)
        .await
        .expect("loopback http lab");
    let spec = DiscoveryTargetSpec::http_loopback_for_tests(&server.url)
        .expect("loopback spec")
        .with_profile(profile)
        .with_timeouts(DiscoveryTimeouts {
            connect: Duration::from_secs(5),
            request: Duration::from_secs(5),
            overall: Duration::from_secs(15),
        });
    let mut client = DiscoveryClient::connect(spec).await.expect("connect");
    let _server = client.discover_server().await.expect("discover");
    let transport = TransportSnapshot {
        kind: TransportKind::StreamableHttp,
        identity: Some("127.0.0.1".to_owned()),
    };
    let revision = match profile {
        PolicyProfile::Current2026_07_28 => CURRENT_WIRE_REVISION,
        PolicyProfile::Legacy2024_11_05 => LEGACY_WIRE_REVISION,
    };
    let outcome = enumerate_inventory(
        &mut client,
        &bounds_with_pages(max_pages),
        envelope(profile, revision, transport),
    )
    .await
    .expect("enumerate");
    let authorized = client.authorized_methods();
    drop(client);
    let methods = trace.snapshot();
    (outcome, methods, authorized, server)
}

#[tokio::test]
async fn streamable_http_current_protocol_is_passive() {
    let (outcome, methods, authorized, server) =
        enumerate_http(PolicyProfile::Current2026_07_28, 32).await;
    assert_passive_trace(&methods, PolicyProfile::Current2026_07_28);
    assert_passive_trace(&authorized, PolicyProfile::Current2026_07_28);
    assert!(
        methods.iter().any(|method| method == "server/discover"),
        "expected server/discover, got {methods:?}"
    );
    assert!(!methods.iter().any(|method| method == "initialize"));
    assert_eq!(outcome.completeness, Completeness::Complete);
    assert_catalog(&outcome.inventory, true);
    assert_evidence(&outcome);
    server.shutdown().await;
}

#[tokio::test]
async fn legacy_initialize_scenario_is_passive() {
    let (outcome, methods, authorized, server) =
        enumerate_http(PolicyProfile::Legacy2024_11_05, 32).await;
    assert_passive_trace(&methods, PolicyProfile::Legacy2024_11_05);
    assert_passive_trace(&authorized, PolicyProfile::Legacy2024_11_05);
    assert!(
        methods.iter().any(|method| method == "initialize"),
        "expected initialize, got {methods:?}"
    );
    assert!(methods
        .iter()
        .any(|method| method == "notifications/initialized"));
    assert!(!methods.iter().any(|method| method == "server/discover"));
    assert_catalog(&outcome.inventory, true);
    server.shutdown().await;
}

#[tokio::test]
async fn multi_page_tools_catalog_completes_without_content_fetch() {
    let (outcome, methods, _, server) = enumerate_http(PolicyProfile::Current2026_07_28, 32).await;
    let tool_lists = methods
        .iter()
        .filter(|method| *method == "tools/list")
        .count();
    assert!(
        tool_lists >= 3,
        "8 tools at page size 3 require at least 3 list pages, got {methods:?}"
    );
    assert_eq!(outcome.inventory.tools.len(), TOOL_NAMES.len());
    assert_eq!(outcome.completeness, Completeness::Complete);
    assert_passive_trace(&methods, PolicyProfile::Current2026_07_28);
    server.shutdown().await;
}

#[tokio::test]
async fn configured_max_pages_produces_typed_partial() {
    let (outcome, methods, _, server) = enumerate_http(PolicyProfile::Current2026_07_28, 1).await;
    assert_eq!(outcome.completeness, Completeness::Partial);
    assert_eq!(outcome.inventory.completeness, Completeness::Partial);
    assert!(outcome
        .inventory
        .warnings
        .iter()
        .any(|warning| warning.code == WarningCode::PaginationLimitReached));
    assert_eq!(outcome.inventory.tools.len(), TOOL_PAGE_SIZE);
    assert_passive_trace(&methods, PolicyProfile::Current2026_07_28);
    assert_catalog(&outcome.inventory, false);
    server.shutdown().await;
}

#[tokio::test]
async fn discovery_never_calls_forbidden_methods() {
    let (outcome, methods, authorized, server) =
        enumerate_http(PolicyProfile::Current2026_07_28, 32).await;
    for method in FORBIDDEN {
        assert!(
            !methods.iter().any(|observed| observed == method),
            "{method} reached the lab: {methods:?}"
        );
        assert!(
            !authorized.iter().any(|observed| observed == method),
            "{method} was authorized by the adapter: {authorized:?}"
        );
        assert!(
            !outcome
                .invoked_methods
                .iter()
                .any(|observed| observed == method),
            "{method} was invoked by enumeration: {:?}",
            outcome.invoked_methods
        );
    }
    server.shutdown().await;
}

#[tokio::test]
async fn production_http_constructor_keeps_tls_required() {
    let err = DiscoveryTargetSpec::http("http://127.0.0.1:9/mcp").expect_err("tls");
    assert!(matches!(err, dare_mcp_discovery::AdapterError::TlsRequired));
    assert!(!err.to_string().contains(CANARY));
}

fn assert_evidence(outcome: &EnumerationOutcome) {
    let observed = outcome.inventory.generated_at;
    let observation = DiscoveryObservation::from_enumeration_outcome(
        outcome,
        PolicyProfile::Current2026_07_28,
        observed,
        observed,
    );
    let records = emit_baseline_evidence(&observation).expect("evidence");
    assert_eq!(records.len(), 4);
    for record in records {
        let value = serde_json::to_value(&record).expect("evidence json");
        dare_security_evidence::validate_instance(&value).expect("evidence schema");
        let encoded = value.to_string();
        assert!(!encoded.contains(CANARY));
        assert!(!encoded.contains("tools/call"));
    }
}
