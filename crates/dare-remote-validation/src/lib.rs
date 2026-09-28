//! Remote validation of authorized targets (Cycle 022).
//!
//! # Live capture, offline verdict
//!
//! This crate is the only component that talks to a remote target, and it
//! decides nothing. It sends pre-approved payloads from digest-pinned engine
//! scenarios to origins an admitted authorization names exactly, records every
//! exchange in a digest-chained capture, and hands that capture to the owning
//! engine's existing offline input. The engine decides the verdict exactly as
//! it does for any replayed or static evidence, so `validate replay-capture`
//! reproduces every result byte for byte without opening a socket.
//!
//! # Boundaries
//!
//! - Authorization is checked before any DNS lookup or socket (`authorization`).
//! - Every request goes through one gateway: HTTPS only, no proxy, no
//!   redirects, DNS pinned per run, private and metadata addresses refused,
//!   spacing rate limit, budget and kill switch (`gateway`, `resolver`,
//!   `address`).
//! - A credential is read from an environment variable the authorization names,
//!   held in zeroizing memory, and scrubbed from everything before it is
//!   recorded (`credential`).
//! - No method with a side effect exists (`protocol`).
//! - No transport outcome can produce PASS (`outcome`).

pub mod address;
pub mod audit;
pub mod authorization;
pub mod canonical;
pub mod capture;
pub mod control;
pub mod credential;
pub mod error;
pub mod ids;
pub mod limits;
pub mod origin;
pub mod outcome;
pub mod plan;
pub mod protocol;
pub mod resolver;
pub mod schema;
pub mod source;

pub use error::{AuthorizationRefusal, EgressRefusal, RemoteError, Result};

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    const MANIFEST: &str = include_str!("../Cargo.toml");

    /// Network stacks, TLS back ends, resolvers and model clients other than
    /// the one this crate is allowed to use.
    const FORBIDDEN_RUNTIME: [&str; 22] = [
        "rmcp",
        "hyper",
        "hyper-util",
        "hyper-rustls",
        "ureq",
        "curl",
        "isahc",
        "surf",
        "attohttpc",
        "openssl",
        "native-tls",
        "hickory-resolver",
        "trust-dns-resolver",
        "async-std",
        "rand",
        "async-openai",
        "anthropic-sdk",
        "openai",
        "llm",
        "ollama-rs",
        "duct",
        "rcgen",
    ];

    /// Dependency names declared in one manifest section.
    fn section(manifest: &str, header: &str) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        let mut inside = false;
        for line in manifest.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                inside = trimmed == header;
                continue;
            }
            if inside && !trimmed.is_empty() && !trimmed.starts_with('#') {
                if let Some(name) = trimmed.split('=').next() {
                    names.insert(name.trim().to_owned());
                }
            }
        }
        names
    }

    fn forbidden_runtime(manifest: &str) -> Vec<&'static str> {
        let runtime = section(manifest, "[dependencies]");
        FORBIDDEN_RUNTIME
            .into_iter()
            .filter(|name| runtime.contains(*name))
            .collect()
    }

    #[test]
    fn the_only_network_stack_is_reqwest() {
        let found = forbidden_runtime(MANIFEST);
        assert!(found.is_empty(), "{found:?} is a second way out");
        assert!(section(MANIFEST, "[dependencies]").contains("reqwest"));
    }

    #[test]
    fn the_check_catches_a_forbidden_runtime_dependency() {
        for (line, name) in [
            ("rmcp = { workspace = true }", "rmcp"),
            ("hyper = \"1\"", "hyper"),
            ("openssl = \"0.10\"", "openssl"),
            ("hickory-resolver = \"0.24\"", "hickory-resolver"),
        ] {
            let manifest =
                MANIFEST.replacen("[dependencies]\n", &format!("[dependencies]\n{line}\n"), 1);
            assert_eq!(forbidden_runtime(&manifest), vec![name]);
        }
    }

    #[test]
    fn a_test_only_dependency_is_not_a_runtime_dependency() {
        let manifest = format!("{MANIFEST}\nhyper = \"1\"\n");
        assert!(forbidden_runtime(&manifest).is_empty());
    }

    #[test]
    fn the_manifest_check_actually_sees_dependencies() {
        let runtime = section(MANIFEST, "[dependencies]");
        assert!(runtime.contains("serde_json"));
        assert!(runtime.contains("dare-security-evidence"));
        assert!(section(MANIFEST, "[dev-dependencies]").contains("tempfile"));
    }
}
