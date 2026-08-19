//! Adapter policy mapping, public API surface, and fake client proofs.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use dare_mcp_discovery::adapter::{self, ServerSnapshot};
use dare_mcp_discovery::{
    documented_wire_revision, lifecycle_mode_for, planned_outbound_methods, AdapterError,
    DiscoveryLifecycleMode, DiscoveryTargetSpec, DiscoveryTimeouts, HttpTransportConfig,
    McpDiscoveryClient, PromptSnapshot, ResourceSnapshot, ResourceTemplateSnapshot, StdioLaunch,
    ToolSnapshot, CURRENT_WIRE_REVISION, ENUMERATION_METHODS, LEGACY_WIRE_REVISION,
};
use dare_mcp_discovery::{DiscoveryMethod, PolicyProfile};

const PLANTED: &str = "sk_live_PLANTED_SECRET_VALUE_9f3a";

struct FakeClient {
    server: ServerSnapshot,
}

#[async_trait]
impl McpDiscoveryClient for FakeClient {
    async fn discover_server(&mut self) -> Result<ServerSnapshot, AdapterError> {
        Ok(self.server.clone())
    }

    async fn list_tools(&mut self) -> Result<Vec<ToolSnapshot>, AdapterError> {
        Ok(vec![ToolSnapshot {
            name: "synthetic.lookup".to_owned(),
            title: None,
            description: None,
            input_schema: None,
            annotations: None,
        }])
    }

    async fn list_resources(&mut self) -> Result<Vec<ResourceSnapshot>, AdapterError> {
        Ok(Vec::new())
    }

    async fn list_resource_templates(
        &mut self,
    ) -> Result<Vec<ResourceTemplateSnapshot>, AdapterError> {
        Ok(Vec::new())
    }

    async fn list_prompts(&mut self) -> Result<Vec<PromptSnapshot>, AdapterError> {
        Ok(Vec::new())
    }
}

#[test]
fn planned_methods_match_allowlist_for_each_profile() {
    for profile in [
        PolicyProfile::Current2026_07_28,
        PolicyProfile::Legacy2024_11_05,
    ] {
        let allow = profile.allowlisted_methods();
        for method in planned_outbound_methods(profile) {
            assert!(
                allow.contains(&method),
                "{method} is requested by the adapter but missing from {profile:?} allowlist"
            );
        }
    }
}

#[test]
fn enumeration_methods_are_identical_across_profiles() {
    assert_eq!(
        ENUMERATION_METHODS,
        &[
            DiscoveryMethod::ToolsList.as_str(),
            DiscoveryMethod::ResourcesList.as_str(),
            DiscoveryMethod::ResourceTemplatesList.as_str(),
            DiscoveryMethod::PromptsList.as_str(),
        ]
    );
}

#[test]
fn unsupported_revision_is_typed_and_does_not_guess() {
    let spec = DiscoveryTargetSpec::stdio("mcp-server", Vec::<String>::new())
        .expect("stdio spec")
        .with_revision("2025-11-25");
    let err = spec.expect_err("2025-11-25 must not be accepted as a policy profile");
    let display = err.to_string();
    assert!(display.contains("2025-11-25"));
    assert!(!display.contains(PLANTED));
    match &err {
        AdapterError::UnsupportedRevision { revision } => {
            assert_eq!(revision, "2025-11-25");
        }
        other => panic!("expected UnsupportedRevision, got {other}"),
    }

    let also = DiscoveryTargetSpec::stdio("mcp-server", Vec::<String>::new())
        .expect("stdio spec")
        .with_revision("2099-01-01")
        .expect_err("future revision");
    assert!(matches!(also, AdapterError::UnsupportedRevision { .. }));
}

#[test]
fn supported_revisions_map_without_expanding_allowlist() {
    let current = DiscoveryTargetSpec::stdio("mcp-server", Vec::<String>::new())
        .expect("stdio")
        .with_revision(CURRENT_WIRE_REVISION)
        .expect("current");
    assert_eq!(current.policy_profile, PolicyProfile::Current2026_07_28);
    assert_eq!(current.lifecycle_mode(), DiscoveryLifecycleMode::Discover);
    assert_eq!(
        documented_wire_revision(current.policy_profile),
        CURRENT_WIRE_REVISION
    );

    let legacy = DiscoveryTargetSpec::stdio("mcp-server", Vec::<String>::new())
        .expect("stdio")
        .with_revision(LEGACY_WIRE_REVISION)
        .expect("legacy");
    assert_eq!(legacy.policy_profile, PolicyProfile::Legacy2024_11_05);
    assert_eq!(
        lifecycle_mode_for(legacy.policy_profile),
        DiscoveryLifecycleMode::Initialize
    );
    assert_eq!(
        documented_wire_revision(legacy.policy_profile),
        LEGACY_WIRE_REVISION
    );
}

#[tokio::test]
async fn fake_client_snapshots_are_crate_owned() {
    let mut client = FakeClient {
        server: ServerSnapshot {
            name: "synthetic-mcp".to_owned(),
            version: Some("0.0.1".to_owned()),
            title: None,
            protocol_revision: CURRENT_WIRE_REVISION.to_owned(),
        },
    };
    let server = client.discover_server().await.expect("server");
    assert_eq!(server.name, "synthetic-mcp");
    let tools = client.list_tools().await.expect("tools");
    assert_eq!(tools[0].name, "synthetic.lookup");
}

#[test]
fn public_adapter_api_does_not_reexport_rmcp() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let files = [
        "src/adapter.rs",
        "src/adapter_error.rs",
        "src/adapter_http.rs",
        "src/adapter_stdio.rs",
        "src/lib.rs",
    ];
    let mut public = String::new();
    for rel in files {
        public.push_str(&fs::read_to_string(root.join(rel)).expect("readable"));
    }
    assert!(
        !public.contains("pub use rmcp::"),
        "public adapter API must not `pub use rmcp::...`"
    );
    assert!(
        !public.contains("pub use rmcp "),
        "public adapter API must not re-export rmcp"
    );
}

#[test]
fn adapter_source_calls_policy_guard() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let session = fs::read_to_string(root.join("src/adapter_session.rs")).expect("session");
    let adapter = fs::read_to_string(root.join("src/adapter.rs")).expect("adapter");
    let combined = format!("{session}\n{adapter}");
    assert!(
        combined.contains("PolicyGuardedTransport") && combined.contains("authorize"),
        "adapter must call PolicyGuardedTransport / authorize before SDK dispatch"
    );
    assert!(combined.contains("DefaultPolicy") || combined.contains("gate.authorize"));
}

#[test]
fn timeout_config_is_applied_on_spec_and_http_builder() {
    let timeouts = DiscoveryTimeouts {
        connect: Duration::from_millis(7),
        request: Duration::from_millis(9),
        overall: Duration::from_millis(11),
    };
    let spec = DiscoveryTargetSpec::stdio("mcp-server", Vec::<String>::new())
        .expect("stdio")
        .with_timeouts(timeouts);
    assert_eq!(spec.timeouts.connect, Duration::from_millis(7));
    assert_eq!(spec.timeouts.request, Duration::from_millis(9));
    assert_eq!(spec.timeouts.overall, Duration::from_millis(11));

    let http = HttpTransportConfig::from_timeouts(spec.timeouts, spec.max_response_bytes);
    assert_eq!(http.connect_timeout(), timeouts.connect);
    assert_eq!(http.request_timeout(), timeouts.request);
}

#[test]
fn stdio_launch_is_available_on_public_api() {
    let launch = StdioLaunch::new("mcp-server", vec!["--passive".to_owned()]).expect("launch");
    assert!(!launch.uses_shell());
    let _ = adapter::DEFAULT_MAX_RESPONSE_BYTES;
}
