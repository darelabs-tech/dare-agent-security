//! Runtime OpenTelemetry security (Cycle 025).
//!
//! Reads OTLP/JSON trace exports that the user supplies as local files, and a
//! runtime policy, and judges two things: whether the traced runs stayed inside
//! the policy, and whether the telemetry itself leaks secrets or is too
//! incomplete to support a verdict. A trace is self-reported by the system under
//! test, so no property passes on the absence of a span. The crate emits no
//! telemetry, opens no port and calls nothing: it reads files and returns
//! values.

pub mod admit;
pub mod error;
pub mod limits;

pub use error::{Input, Refusal, Result, TelemetryError};

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    const MANIFEST: &str = include_str!("../Cargo.toml");

    /// Dependencies that could emit or receive telemetry, reach a network,
    /// spawn a process or make a run depend on chance.
    const FORBIDDEN: [&str; 34] = [
        "opentelemetry",
        "opentelemetry_sdk",
        "opentelemetry-sdk",
        "opentelemetry-otlp",
        "opentelemetry-proto",
        "opentelemetry-stdout",
        "tracing-opentelemetry",
        "prost",
        "protobuf",
        "tokio",
        "async-std",
        "axum",
        "actix-web",
        "warp",
        "reqwest",
        "hyper",
        "ureq",
        "curl",
        "isahc",
        "surf",
        "attohttpc",
        "tonic",
        "tokio-tungstenite",
        "rustls",
        "native-tls",
        "openssl",
        "webpki",
        "rand",
        "rand_core",
        "getrandom",
        "fastrand",
        "openai",
        "anthropic",
        "duct",
    ];

    fn forbidden_declared(manifest: &str) -> Vec<&'static str> {
        let declared: BTreeSet<&str> = manifest
            .lines()
            .filter_map(|line| line.split('=').next())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .collect();
        FORBIDDEN
            .into_iter()
            .filter(|name| declared.contains(name))
            .collect()
    }

    #[test]
    fn this_crate_declares_no_telemetry_network_or_generation_dependency() {
        let found = forbidden_declared(MANIFEST);
        assert!(
            found.is_empty(),
            "{found:?} would let this crate emit, receive, send or sample"
        );
    }

    #[test]
    fn the_check_catches_a_forbidden_dependency_when_one_is_added() {
        for (line, name) in [
            ("opentelemetry-otlp = \"0.30\"", "opentelemetry-otlp"),
            ("tokio = { workspace = true }", "tokio"),
            ("prost = \"0.13\"", "prost"),
        ] {
            let manifest = format!("{MANIFEST}\n{line}\n");
            assert_eq!(forbidden_declared(&manifest), vec![name]);
        }
    }

    #[test]
    fn the_manifest_check_actually_sees_dependencies() {
        assert!(MANIFEST.contains("serde_json"));
        assert!(MANIFEST.contains("dare-security-evidence"));
    }
}
