# task-012 — Implement format-independent normalization and semantic digests

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-17, AC-18, AC-20, AC-21, AC-24, AC-25, AC-26

## Evidence

`src/normalize.rs` and `src/canonical.rs`.

**AC-26 — equivalent CycloneDX and SPDX fixtures normalize equivalently.** The comparison is over `semantic_key()`, which deliberately excludes `evidence_source`. If the digest included which parser produced the row, two documents describing the same system would never compare equal and the test would be asserting that CycloneDX is not SPDX — true, and useless.

The equivalence test asserts both halves: that the two imported bundles are **structurally different** (different evidence sources, different document metadata) and **semantically equivalent**. Without the first assertion the test could pass by comparing a bundle to itself.

**AC-17/AC-18/AC-21 — canonical identity and collision detection.** `EvidenceBuilder::build` runs `validate()` on the *assembled* bundle rather than on each document as it arrives, because a cross-document identity collision is invisible from inside either document. Two documents can each be internally consistent and, merged, claim the same identity for different artifacts.

**`merge_into` is union, not replacement.** A second, quieter document cannot remove a digest the first supplied. Replacement semantics would make evidence weaker by adding more of it, which is the wrong direction for a security engine: an attacker who can append a document should not be able to erase a binding.

**`collapse_declared_and_observed`** exists so one dependency that both the manifest declares and the BOM observes reads as one agreeing edge rather than two half-findings — one "declared but not observed" and one "observed but not declared" for the same edge.

**AC-20 — digest algorithms are allowlisted and malformed digests fail closed.** `DigestAlgorithm::hex_len()` pins the expected length per algorithm; a SHA-256 value of the wrong length is refused rather than stored. `ArtifactDigest` accepts lowercase hex only, so `AB...` and `ab...` cannot become two identities for one artifact.

**Canonical digests are order-independent.** Every collection in the model is a `BTreeSet` or `BTreeMap`, and `manifest_collections_are_order_independent` asserts two equivalent manifests digest identically. A reordering that changed the digest would read as a substitution.
