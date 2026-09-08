//! DARE Cycle 019 — agentic supply-chain security and AI-BOM validation.
//!
//! Bounded, deterministic, offline evaluation of whether a set of local
//! bill-of-materials, provenance and attestation evidence shows that component
//! identity, integrity, source trust, provenance, attestation, dependency
//! relationships, model lineage and dataset provenance remain bound to the
//! agentic system that was approved.
//!
//! This is a security decision layer. It is not an SBOM crawler and not a
//! remote package-verification service.
//!
//! # The rules the crate is built on
//!
//! ```text
//! inventory              != trust
//! component name         != component identity
//! version string         != immutable artifact
//! digest presence        != provenance
//! valid signature        != authorized signer
//! provenance presence    != trusted provenance
//! complete AI-BOM        != secure supply chain
//! declared dependency    != observed dependency
//! same name and version  != same artifact
//! component URL          != authorization to fetch
//! external agent listed  != A2A authorization
//! ```
//!
//! Each is a place where two things that look alike are not the same thing.
//! Treating them as the same is how a supply-chain boundary quietly stops
//! existing, and each one has an invariant behind it.
//!
//! # What is never reached
//!
//! No package registry, model hub, container registry, Git host, transparency
//! log, signing service or vulnerability database.
//!
//! This matters more here than in most cycles, because the documents this
//! engine reads are *full of coordinates*. A CycloneDX component carries a
//! purl; an SPDX package carries a download location; an attestation names a
//! repository. Every one of those is a place something could be fetched from,
//! and this engine treats all of them as inert metadata: a coordinate names
//! something, and naming something is not authorization to go and get it.
//!
//! This crate declares no HTTP client, no registry client, no OCI client, no
//! Git library, no model runtime and no archive extractor. It would be an
//! overclaim to say no transport stack exists transitively — `dare-coverage`
//! reaches one through the workspace — so the boundary asserted here is the one
//! that is true and checkable: **nothing in this crate reaches it**, and
//! `tests::this_crate_declares_no_fetch_dependency_of_its_own` fails if a
//! dependency that could appears in the manifest.
//!
//! # What is never executed
//!
//! No artifact, model, script or archive from imported evidence is executed,
//! deserialized into a live object, or loaded. A BOM entry describing a
//! container image is a row in a graph, not something to run.
//!
//! # Boundaries with the cycles around it
//!
//! Cycle 012 owns the Agentic registry and the `AGENTIC_SUPPLY_CHAIN` risk
//! family; its two supply-chain properties are reused unchanged, and this cycle
//! adds eight beside them. Cycle 014 owns runtime tool authorization and
//! misuse — a tool appears here as a component with provenance, and what it is
//! *allowed to do at runtime* is not this cycle's question. Cycle 018 owns MCP
//! authentication; an MCP server appears here as a component. Cycle 020 owns
//! A2A protocol security, so an external agent is inventory here and nothing
//! more. Cycle 023 will build attack paths from a dependency graph; this cycle
//! produces the graph and draws no paths through it.

pub mod attestation;
pub mod budget;
pub mod canonical;
pub mod component;
pub mod cyclonedx;
pub mod error;
pub mod identity;
pub mod manifest;
pub mod normalize;
pub mod provenance;
pub mod relationship;
pub mod schema;
pub mod source;
pub mod spdx;

pub use error::{Result, SupplyChainError};
pub use source::{
    ComponentType, DigestAlgorithm, EvidenceSource, HarnessErrorKind, ObservationKind,
    ReferenceBehavior, ScenarioClass, TrustClass, VerificationStatus,
};

/// Hard bounds approved for Cycle 019.
///
/// Every one is a refusal threshold, never a clamp. A document may declare
/// less; nothing may declare more. The distinction matters because a silently
/// clamped input runs as though it had asked for something reasonable, and the
/// operator never learns their document was out of bounds.
///
/// Run-wide totals are enforced across the whole run and never reset between
/// components or trials. A counter that resets is not a bound.
pub mod limits {
    /// Bytes of raw BOM input admitted before anything is parsed.
    pub const HARD_MAX_BOM_BYTES: usize = 16_777_216;
    /// Components admitted into the normalized model.
    pub const HARD_MAX_COMPONENTS: u32 = 2_048;
    /// Relationship edges admitted into the graph.
    pub const HARD_MAX_RELATIONSHIPS: u32 = 8_192;
    /// Depth a dependency walk may reach before it is refused as a graph bomb.
    pub const HARD_MAX_DEPENDENCY_DEPTH: u32 = 64;
    /// Attestations one component may carry.
    pub const HARD_MAX_ATTESTATIONS_PER_COMPONENT: u32 = 16;
    /// Provenance records one component may carry.
    pub const HARD_MAX_PROVENANCE_RECORDS_PER_COMPONENT: u32 = 16;
    /// Digests one component may carry.
    pub const HARD_MAX_HASHES_PER_COMPONENT: u32 = 8;
    /// Identifiers one component may carry.
    pub const HARD_MAX_IDENTIFIERS_PER_COMPONENT: u32 = 16;
    /// Bytes of free-form metadata one component may carry.
    pub const HARD_MAX_METADATA_BYTES_PER_COMPONENT: usize = 32_768;
    /// Capability entries one component may declare.
    pub const HARD_MAX_CAPABILITIES_PER_COMPONENT: u32 = 256;

    /// Trials executed when a scenario does not say otherwise.
    pub const DEFAULT_TRIALS: u32 = 3;
    /// Absolute ceiling on trials, whatever a scenario or flag requests.
    pub const HARD_MAX_TRIALS: u32 = 10;
    /// Stop the run once a trial has failed — after that trial's evidence has
    /// been fully collected, never before.
    pub const STOP_ON_FIRST_FAIL: bool = true;

    /// Bytes of observation evidence one trial may retain.
    pub const MAX_OUTPUT_BYTES_PER_TRIAL: usize = 1_048_576;
    /// Bytes of observation evidence a whole run may retain.
    pub const MAX_TOTAL_OUTPUT_BYTES: usize = 8_388_608;

    /// Product state changes. Zero, and the type system has no way to express
    /// one.
    pub const MAX_STATE_CHANGES: u32 = 0;
    /// Bytes that may leave the process. Zero.
    pub const EXTERNAL_EGRESS_BYTES: u64 = 0;

    /// Bytes of free-form evidence text retained per observation.
    pub const MAX_EVIDENCE_TEXT_BYTES: usize = 512;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_approved_bounds_are_exactly_what_design_records() {
            // Pinned against `DESIGN.md` §24. A bound that drifted from the
            // approval would be a scope change nobody reviewed.
            assert_eq!(HARD_MAX_BOM_BYTES, 16_777_216);
            assert_eq!(HARD_MAX_COMPONENTS, 2_048);
            assert_eq!(HARD_MAX_RELATIONSHIPS, 8_192);
            assert_eq!(HARD_MAX_DEPENDENCY_DEPTH, 64);
            assert_eq!(HARD_MAX_ATTESTATIONS_PER_COMPONENT, 16);
            assert_eq!(HARD_MAX_PROVENANCE_RECORDS_PER_COMPONENT, 16);
            assert_eq!(HARD_MAX_HASHES_PER_COMPONENT, 8);
            assert_eq!(HARD_MAX_IDENTIFIERS_PER_COMPONENT, 16);
            assert_eq!(HARD_MAX_METADATA_BYTES_PER_COMPONENT, 32_768);
            assert_eq!(HARD_MAX_CAPABILITIES_PER_COMPONENT, 256);
            assert_eq!(HARD_MAX_TRIALS, 10);
            assert_eq!(DEFAULT_TRIALS, 3);
            assert_eq!(MAX_OUTPUT_BYTES_PER_TRIAL, 1_048_576);
            assert_eq!(MAX_TOTAL_OUTPUT_BYTES, 8_388_608);
        }

        #[test]
        fn the_zero_bounds_are_zero_and_stay_that_way() {
            const { assert!(MAX_STATE_CHANGES == 0) };
            const { assert!(EXTERNAL_EGRESS_BYTES == 0) };
        }

        #[test]
        fn per_component_bounds_never_exceed_run_wide_ones() {
            // A per-unit bound above the run total would be unreachable, which
            // usually means one of the two was edited without the other.
            const { assert!(MAX_OUTPUT_BYTES_PER_TRIAL <= MAX_TOTAL_OUTPUT_BYTES) };
            const { assert!(HARD_MAX_COMPONENTS <= HARD_MAX_RELATIONSHIPS) };
        }

        #[test]
        fn the_dependency_depth_ceiling_is_small_enough_to_stop_a_bomb() {
            // A graph 64 deep is already implausible for a real dependency
            // tree. A generous ceiling would let a crafted document walk the
            // engine into a stall and call the result evidence.
            const { assert!(HARD_MAX_DEPENDENCY_DEPTH <= 128) };
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn this_crate_declares_no_fetch_dependency_of_its_own() {
        // The offline boundary, checked against the manifest rather than
        // asserted in prose.
        //
        // The documents this engine reads are full of coordinates — a purl, a
        // download location, a repository reference. The claim is not that
        // those coordinates are absent; it is that this crate has no dependency
        // through which one could become a request.
        let manifest = include_str!("../Cargo.toml");
        let dependencies = manifest
            .split("[dependencies]")
            .nth(1)
            .expect("a dependencies section");
        for forbidden in [
            "reqwest",
            "hyper",
            "ureq",
            "curl",
            "rustls",
            "native-tls",
            "openssl",
            "git2",
            "gix",
            "oci-",
            "oci_",
            "docker",
            "tar",
            "zip",
            "flate2",
            "tokio",
            "async-std",
            "candle",
            "ort",
            "onnx",
            "pyo3",
            "libloading",
        ] {
            assert!(
                !dependencies.contains(forbidden),
                "this crate declares `{forbidden}`, through which a coordinate could become a \
                 request or a byte stream could become an execution"
            );
        }
    }

    #[test]
    fn no_constant_in_this_crate_holds_a_reachable_endpoint() {
        // The narrower claim, and the one that is actually true.
        //
        // A first version of this test scanned every source line for `://` and
        // failed immediately — because the crate *must* contain URL-shaped
        // strings. `schema.rs` lists `file://` and `javascript:` in order to
        // refuse them, and the tests use `https://registry.npmjs.org/react` as
        // a hostile fixture. Banning the characters would have meant deleting
        // the checks that keep them out of admitted documents.
        //
        // What would actually be dangerous is a *constant* holding an endpoint:
        // a default registry, a base URL, a well-known path. That is where a
        // fetch would start if this crate ever grew one, and unlike a refusal
        // list it has no legitimate reason to exist.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut pending = vec![root];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).expect("source directory") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().is_none_or(|ext| ext != "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("readable");
                for line in text.lines() {
                    let trimmed = line.trim_start();
                    let is_declaration = trimmed.starts_with("const ")
                        || trimmed.starts_with("static ")
                        || trimmed.starts_with("pub const ")
                        || trimmed.starts_with("pub static ");
                    if !is_declaration {
                        continue;
                    }
                    assert!(
                        !line.contains("://"),
                        "{} declares a constant holding an endpoint: {}",
                        path.display(),
                        line.trim()
                    );
                }
            }
        }
    }
}
