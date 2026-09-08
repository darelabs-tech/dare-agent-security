# task-007 — Define DARE Agentic Supply Chain Manifest schema without verdict authority

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-27, AC-28

## Evidence

`src/manifest.rs`.

Every other module in this crate reads a document that describes **what a system contains**. This module reads the only document that describes **what was approved**, and that asymmetry is the whole trust model. A CycloneDX document can say a component is supplied by Acme; it cannot say Acme was approved. `inventory != trust` is enforced here and in `SourceTrustAssessment::validate`, which refuses an `Approved` trust class arriving from any source other than a local approval.

**AC-27 — the manifest expresses identity, trust and relationship expectations.** `TrustPolicy` carries five separate approved-identity sets, `approved_components` carries approved identities with their digests, `expected_edges` carries the dependency shape, `expected_lineage` carries base models and `approved_capabilities` carries capability sets.

The five identity sets are separate because they are five separate concepts: a publisher is not a builder and a builder is not a signer. `the_five_approved_identity_sets_are_separate_concepts` asserts that approving `builder-ci` as a builder does not approve it as a signer. Collapsing them into one `approved_identities` set would have made every approval broader than anyone wrote it.

**`ExpectedLineage` names a base by id, never by name.** `model name alone cannot prove lineage` is the defect the property exists to catch; expressing the expectation as a name would have built the defect into the expectation. `expected_lineage_is_expressed_as_an_id_and_not_a_name` asserts that a `base_name` field fails to decode.

**An empty policy is a gap, not universal denial.** `an_absent_policy_is_a_gap_rather_than_universal_denial`. Denying everything makes every component a finding, which is indistinguishable from a broken engine, and an operator learns to ignore the output either way. `approves_origin` returns `Option<bool>`: `None` when no claim exists at all, `Some(false)` when a claim was checked and matched nothing. Those are different situations and the evaluators treat them differently.

**AC-28 — a manifest cannot declare a verdict.** Structural rather than checked. There is no field for an outcome and `deny_unknown_fields` means adding one fails to decode. `a_manifest_cannot_declare_a_verdict` asserts four shapes are refused: `expected_verdict`, `is_secure`, `expected_findings` and `should_fail`.

This is the discipline that keeps paired fixtures meaningful. A manifest that could state an outcome would reduce the engine to agreeing with whoever wrote the manifest, and every SUPPLY-LAB pair would then be testing the fixture author rather than the engine.

**An unknown schema version is refused, not guessed.** `an_unsupported_manifest_version_is_refused_rather_than_guessed`. Guessing what version 2 meant is how an approved expectation quietly changes meaning without anyone editing it.
