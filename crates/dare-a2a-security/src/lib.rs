//! DARE Cycle 020 — A2A and inter-agent communication security.
//!
//! Bounded, deterministic, offline evaluation of whether a peer, a message, an
//! authority, a task context, a tenant, a data scope and a protocol stayed
//! correctly bound across an inter-agent exchange.
//!
//! This is a security decision layer. It is not an A2A client, not a protocol
//! conformance suite and not a remote agent scanner.
//!
//! # The rules the crate is built on
//!
//! ```text
//! external agent listed          != trusted peer
//! discovered Agent Card          != authenticated identity
//! signed Agent Card              != authorized provider
//! TLS server identity            != agent-level authorization
//! declared security scheme       != successful authentication
//! successful authentication      != skill authorization
//! schema-valid message           != authentic message
//! authentic message              != authorized instruction
//! peer content                   != privileged instruction
//! taskId match                   != principal/context match
//! delegation                     != privilege amplification
//! message retry                  != safe replay
//! protocol compatibility         != permission to downgrade
//! extension declaration          != extension authority
//! webhook URL                    != permission to connect
//! tenant routing value           != proof of tenant authorization
//! ```
//!
//! Each is a place where two things that look alike are not the same thing.
//! Treating them as the same is how an inter-agent boundary quietly stops
//! existing, and each one has an invariant behind it.
//!
//! # What is never reached
//!
//! No live agent, endpoint, `.well-known` location, registry, key server,
//! authorization server, token endpoint, transparency log or webhook.
//!
//! This matters more here than in most cycles, because the documents this
//! engine reads are *made of places*. An Agent Card lists interface URLs; a
//! security scheme names a token endpoint; a signature header carries a `jku`;
//! a push notification configuration is a URL by construction. Every one of
//! those is somewhere a request could go, and this engine treats all of them as
//! inert metadata: a URL names a place, and naming a place is not authorization
//! to go there.
//!
//! This crate declares no HTTP client, no OAuth client, no JWT verifier, no
//! JWKS resolver, no TLS stack and no process spawner. It would be an overclaim
//! to say no transport stack exists transitively — `dare-coverage` reaches one
//! through the workspace — so the boundary asserted here is the one that is
//! true and checkable: **nothing in this crate reaches it**, and
//! `tests::this_crate_declares_no_network_dependency_of_its_own` fails if a
//! dependency that could appears in the manifest.
//!
//! # What is never performed
//!
//! No signature is verified, no key is resolved, no token is obtained,
//! exchanged or introspected, no TLS handshake occurs and no certificate is
//! validated. Where the engine reports on any of those, it is reading a status
//! that a *different* verifier recorded — and
//! [`source::VerificationStatus`] keeps "a status was recorded" and "the status
//! was favourable" in different answers, because Cycle 018 paid for conflating
//! them.
//!
//! # Boundaries with the cycles around it
//!
//! Cycle 013 owns generalized prompt injection: this engine detects that
//! peer-controlled content crossed into an authority position, and does not
//! classify the injection technique. Cycle 014 owns tool-invocation
//! authorization: a remote *skill* is not a local *tool*, and this engine never
//! decides whether a tool may run. Cycle 015 owns principal, delegation,
//! privilege and tenant semantics: this engine evaluates only their A2A
//! projection. Cycle 019 owns external-agent inventory: an agent appearing in a
//! bill of materials is a row in an inventory, and this cycle is where the
//! question of whether it may be talked to begins.
//!
//! Cycles 021, 022 and 023 own adaptive multi-turn adversarial execution,
//! remote authorized validation and attack-path construction. None of them is
//! implemented here.

pub mod agent_card;
pub mod authentication;
pub mod authorization;
pub mod budget;
pub mod canonical;
pub mod data_scope;
pub mod delegation;
pub mod error;
pub mod extension;
pub mod message;
pub mod normalize;
pub mod peer;
pub mod policy;
pub mod protocol;
pub mod push_notification;
pub mod replay;
pub mod schema;
pub mod source;
pub mod tenant;

pub use error::{A2aSecurityError, Result};

/// The bounds this cycle runs under.
///
/// Every one is a hard maximum rather than a default, and the two that are zero
/// are the ones the whole safety boundary rests on.
pub mod limits {
    /// Bytes of a single imported document (Agent Card, trace, policy).
    pub const HARD_MAX_DOCUMENT_BYTES: usize = 4_194_304;
    /// Peers admitted in one run.
    pub const HARD_MAX_PEERS: u32 = 256;
    /// Exchanges (messages/tasks) admitted in one run.
    pub const HARD_MAX_EXCHANGES: u32 = 2_048;
    /// Parts inside one message.
    pub const HARD_MAX_PARTS_PER_MESSAGE: u32 = 64;
    /// Artifacts referenced by one exchange.
    pub const HARD_MAX_ARTIFACTS_PER_EXCHANGE: u32 = 64;
    /// Skills declared by one Agent Card.
    pub const HARD_MAX_SKILLS_PER_CARD: u32 = 256;
    /// Interfaces declared by one Agent Card.
    pub const HARD_MAX_INTERFACES_PER_CARD: u32 = 32;
    /// Security schemes declared by one Agent Card.
    pub const HARD_MAX_SECURITY_SCHEMES_PER_CARD: u32 = 32;
    /// Extensions declared or used.
    pub const HARD_MAX_EXTENSIONS: u32 = 64;
    /// Hops in one delegation chain.
    pub const HARD_MAX_DELEGATION_DEPTH: u32 = 16;
    /// Data-scope labels carried by one exchange.
    pub const HARD_MAX_DATA_LABELS: u32 = 64;
    /// Bytes of bounded free-form metadata retained per object.
    pub const HARD_MAX_METADATA_BYTES: usize = 16_384;
    /// Bytes of retained evidence text per observation, after redaction.
    pub const MAX_EVIDENCE_TEXT_BYTES: usize = 512;
    /// JSON nesting depth. Deeper is a stack-exhaustion attempt dressed as
    /// data.
    pub const HARD_MAX_JSON_DEPTH: usize = 64;

    /// Trials one run may execute.
    pub const HARD_MAX_TRIALS: u32 = 10;
    pub const DEFAULT_TRIALS: u32 = 3;

    /// Bytes one trial may retain.
    pub const MAX_OUTPUT_BYTES_PER_TRIAL: usize = 1_048_576;
    /// Bytes one run may retain in total, artifacts included.
    pub const MAX_TOTAL_OUTPUT_BYTES: usize = 8_388_608;

    /// Product state changes. Zero, and it stays zero.
    pub const MAX_STATE_CHANGES: u32 = 0;
    /// External egress bytes. Zero, and it stays zero.
    pub const EXTERNAL_EGRESS_BYTES: u64 = 0;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_zero_bounds_are_zero_and_stay_that_way() {
            const { assert!(MAX_STATE_CHANGES == 0) };
            const { assert!(EXTERNAL_EGRESS_BYTES == 0) };
        }

        #[test]
        fn per_unit_bounds_never_exceed_run_wide_ones() {
            // A per-unit bound above the run total would be unreachable, which
            // usually means one of the two was edited without the other.
            const { assert!(MAX_OUTPUT_BYTES_PER_TRIAL <= MAX_TOTAL_OUTPUT_BYTES) };
            const { assert!(HARD_MAX_PEERS <= HARD_MAX_EXCHANGES) };
            const { assert!(MAX_EVIDENCE_TEXT_BYTES <= HARD_MAX_METADATA_BYTES) };
        }

        #[test]
        fn the_json_depth_ceiling_is_small_enough_to_stop_a_bomb() {
            // A document nested 64 deep is already implausible. A generous
            // ceiling would let a crafted card walk the parser into a stall and
            // call the result evidence.
            const { assert!(HARD_MAX_JSON_DEPTH <= 128) };
        }

        #[test]
        fn the_delegation_depth_ceiling_is_small_enough_to_be_reviewable() {
            // A chain nobody can hold in their head is a chain nobody audits,
            // and each hop is an opportunity for authority to widen.
            const { assert!(HARD_MAX_DELEGATION_DEPTH <= 32) };
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    const MANIFEST: &str = include_str!("../Cargo.toml");

    /// Dependencies through which a coordinate in an Agent Card could become a
    /// request, a token or a verified signature.
    const FETCH_CAPABLE: [&str; 18] = [
        "reqwest",
        "hyper",
        "ureq",
        "curl",
        "isahc",
        "surf",
        "attohttpc",
        "tonic",
        "tokio-tungstenite",
        "oauth2",
        "openidconnect",
        "jsonwebtoken",
        "jwt",
        "josekit",
        "rustls",
        "native-tls",
        "openssl",
        "webpki",
    ];

    #[test]
    fn this_crate_declares_no_network_dependency_of_its_own() {
        // The boundary that is actually checkable. Every document this engine
        // reads is made of places a request could go; what stops one going is
        // that no dependency here could send it.
        let declared: BTreeSet<&str> = MANIFEST
            .lines()
            .filter_map(|line| line.split('=').next())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .collect();

        for forbidden in FETCH_CAPABLE {
            assert!(
                !declared.contains(forbidden),
                "`{forbidden}` would give this crate a way to resolve a coordinate it reads"
            );
        }
    }

    #[test]
    fn no_constant_in_this_crate_holds_a_reachable_endpoint() {
        // The narrower claim, and the one that is actually true.
        //
        // The crate *must* contain URL-shaped strings: `schema.rs` lists
        // forbidden schemes in order to refuse them, and the corpus stages
        // hostile Agent Cards carrying `jku` and webhook values precisely so
        // the engine can prove it does not follow them. Banning the characters
        // would mean deleting the checks that keep them out.
        //
        // What would actually be dangerous is a *constant* holding an endpoint:
        // a default registry, a well-known path, a base URL. That is where a
        // request would start if this crate ever grew one, and unlike a refusal
        // list it has no legitimate reason to exist.
        let sources = [
            include_str!("agent_card.rs"),
            include_str!("authentication.rs"),
            include_str!("message.rs"),
            include_str!("peer.rs"),
            include_str!("policy.rs"),
            include_str!("push_notification.rs"),
            include_str!("schema.rs"),
        ];

        for source in sources {
            for line in source.lines() {
                let trimmed = line.trim_start();
                if !(trimmed.starts_with("const ")
                    || trimmed.starts_with("static ")
                    || trimmed.starts_with("pub const ")
                    || trimmed.starts_with("pub static "))
                {
                    continue;
                }
                for scheme in ["http://", "https://", "ws://", "wss://"] {
                    assert!(
                        !line.contains(scheme),
                        "a constant holds a reachable endpoint: {}",
                        line.trim()
                    );
                }
            }
        }
    }
}
