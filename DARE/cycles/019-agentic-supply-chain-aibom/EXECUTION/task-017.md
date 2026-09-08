# task-017 — Implement local attestation/signature evidence binding with zero remote verification

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-11, AC-12, AC-34, AC-35, AC-36, AC-37

## Evidence

`src/attestation.rs`.

**AC-34 — the subject digest binds to the assessed artifact.** `binds_subject_digest()` is the deciding check; `names_component()` is the weaker one that only says the record mentions the component. An attestation whose subject digest does not match is an attestation for a different build, and the assessment keeps `misbound_attestation_ids` **separate from having no attestation at all**.

That separation is the point. "No attestation" and "an attestation that binds the wrong artifact" collapse into the same INCONCLUSIVE if the model only counts matches — and the second is a substitution finding, not a gap.

**AC-35 — local verification status is not signer trust.** The status records what a local check found. Whether the signer was approved is `TrustPolicy::approves_signer`, evaluated separately against a local policy. A cryptographically valid signature by an unapproved signer is a valid signature and an unauthorized one.

**AC-36 — an unapproved signer can fail its invariant deterministically**, distinct from an absent policy, which is a gap.

**AC-11/AC-12/AC-37 — no remote verification of any kind.** No Fulcio, no Rekor, no OCI registry, no transparency log, no key server. Sigstore and Cosign are recorded as **INFORMATIVE** in `standards/supply-chain-security/2026/provenance.json`, not normative, because this engine reads their evidence shapes and never performs their protocols.

The refusal is structural: the crate declares no HTTP, OCI or Git dependency (`this_crate_declares_no_fetch_dependency_of_its_own`), `transparency_log_url` and its neighbours are in `FORBIDDEN_FETCH_FIELDS`, and `no_constant_in_this_crate_holds_a_reachable_endpoint` asserts no `const` or `static` holds a place a fetch could start from.
