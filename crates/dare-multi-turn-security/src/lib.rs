//! DARE Cycle 021 — adaptive multi-turn adversarial execution.
//!
//! Bounded, deterministic, offline evaluation of whether an agent keeps a
//! security property across a *conversation*: a refusal that must survive
//! rephrasing, an objective split into innocent-looking fragments, authority
//! accumulated through claimed roles, an instruction planted on one turn and
//! triggered on a later one, an approval given for one action and spent on
//! another.
//!
//! # What "adaptive" means here, and what it never means
//!
//! ```text
//! adaptive          == the next turn is SELECTED from an approved, finite,
//!                      acyclic strategy graph by a CLOSED observation class
//! adaptive          != a turn is generated, mutated, templated or paraphrased
//! observation class != verdict            (classes steer; facts decide)
//! strategy exhausted != target secure     (only the path taken is claimed)
//! stop before terminal != PASS
//! ```
//!
//! Every turn this engine can ever send is a node of a graph whose digest was
//! pinned before the run started. Nothing is sampled, so identical inputs give
//! byte-identical artifacts.
//!
//! # What is never reached
//!
//! No model, provider, endpoint or remote agent. Live and remote targets belong
//! to Cycle 022. This crate declares no HTTP client, TLS stack, process
//! spawner, random-number generator or model client, and
//! `tests::this_crate_declares_no_network_or_generation_dependency` fails if one
//! appears in the manifest.
//!
//! # Boundaries with the cycles around it
//!
//! Single-turn verdict authority stays where it was: prompt injection with
//! Cycle 013, tool authorization with 014, principal and delegation semantics
//! with 015, memory storage with 016, inter-agent exchanges with 020. This
//! engine decides only properties that exist *across* turns. Cycle 006 owns
//! coverage math and Cycle 018 owns concrete-FAIL aggregation. Cycles 022–025
//! (remote validation, attack paths, blast radius, runtime telemetry) are not
//! implemented here.

pub mod error;
pub mod ids;
pub mod limits;
pub mod schema;
pub mod source;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    const MANIFEST: &str = include_str!("../Cargo.toml");

    /// Dependencies that could reach a model or a network, spawn a process or
    /// make a run depend on chance.
    const FORBIDDEN: [&str; 24] = [
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
        "nanorand",
        "async-openai",
        "openai",
        "anthropic",
        "llm",
        "ollama-rs",
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
    fn this_crate_declares_no_network_or_generation_dependency() {
        let found = forbidden_declared(MANIFEST);
        assert!(
            found.is_empty(),
            "{found:?} would let this crate generate, sample or send"
        );
    }

    #[test]
    fn the_check_catches_a_forbidden_dependency_when_one_is_added() {
        for (line, name) in [
            ("rand = \"0.8\"", "rand"),
            ("reqwest = { workspace = true }", "reqwest"),
            ("async-openai = \"0.20\"", "async-openai"),
        ] {
            let manifest = format!("{MANIFEST}\n{line}\n");
            assert_eq!(forbidden_declared(&manifest), vec![name]);
        }
    }

    #[test]
    fn the_manifest_check_actually_sees_dependencies() {
        // Guard against the check above passing vacuously.
        assert!(MANIFEST.contains("serde_json"));
        assert!(MANIFEST.contains("dare-adversarial"));
    }
}
