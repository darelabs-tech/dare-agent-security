//! HTTP transport policy: TLS required, redirects disabled.

use std::time::Duration;

use dare_mcp_discovery::{
    AdapterError, DiscoveryTargetSpec, DiscoveryTimeouts, HttpTransportConfig,
};

const PLANTED: &str = "sk_live_PLANTED_SECRET_VALUE_9f3a";

#[test]
fn redirect_policy_is_disabled_and_tls_is_required() {
    let cfg = HttpTransportConfig::new();
    assert!(!cfg.follow_redirects());
    assert!(cfg.tls_verify());
    assert!(cfg.https_only());
    cfg.build_reqwest_client()
        .expect("safe default client must build");
}

#[test]
fn http_spec_rejects_cleartext_and_does_not_echo_url() {
    let err = DiscoveryTargetSpec::http("http://mcp.example.test/mcp").expect_err("http");
    assert_eq!(err, AdapterError::TlsRequired);
    let display = err.to_string();
    assert!(!display.contains("mcp.example.test"));
    assert!(!display.contains("http://"));
}

#[test]
fn https_spec_is_accepted() {
    let spec = DiscoveryTargetSpec::http("https://mcp.example.test/mcp").expect("https");
    match spec.target {
        dare_mcp_discovery::DiscoveryTargetKind::Http { url } => {
            assert_eq!(url, "https://mcp.example.test/mcp");
        }
        dare_mcp_discovery::DiscoveryTargetKind::Stdio { .. } => panic!("expected http"),
    }
}

#[test]
fn credentials_are_refused_without_echo() {
    let raw = format!("https://bearer:{PLANTED}@mcp.example.test/mcp");
    let err = DiscoveryTargetSpec::http(&raw).expect_err("credentials");
    let display = err.to_string();
    let debug = format!("{err:?}");
    assert!(!display.contains(PLANTED));
    assert!(!debug.contains(PLANTED));
    assert!(!display.contains("bearer:"));
}

#[test]
fn timeout_and_body_bounds_are_copied_onto_http_config() {
    let timeouts = DiscoveryTimeouts {
        connect: Duration::from_secs(3),
        request: Duration::from_secs(4),
        overall: Duration::from_secs(5),
    };
    let spec = DiscoveryTargetSpec::http("https://mcp.example.test/mcp")
        .expect("https")
        .with_timeouts(timeouts)
        .with_max_response_bytes(2048)
        .expect("bound");
    let cfg = HttpTransportConfig::from_timeouts(spec.timeouts, spec.max_response_bytes);
    assert_eq!(cfg.connect_timeout(), Duration::from_secs(3));
    assert_eq!(cfg.request_timeout(), Duration::from_secs(4));
    assert_eq!(cfg.max_response_bytes(), 2048);
    assert!(!cfg.follow_redirects());
    assert!(cfg.tls_verify());
}
