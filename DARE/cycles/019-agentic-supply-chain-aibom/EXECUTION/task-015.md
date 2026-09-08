# task-015 — Define source/publisher/builder/signer trust policy evidence model

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-33, AC-35, AC-36

## Evidence

`src/component.rs` (`SupplierClaim`, `SourceTrustAssessment`, `TrustClass`) and `src/source.rs`.

```text
inventory                != trust
valid signature evidence != authorized signer
```

**The asymmetry is structural, not procedural.** `SourceTrustAssessment::validate` **refuses** a `TrustClass::Approved` whose `evidence_source` cannot establish approval — `EvidenceSource::may_establish_approval()` returns true only for `DareManifest` and `LocalPolicy`. A BOM claiming its own component is approved does not produce a weaker approval; it produces an error.

This matters because the alternative is a rule every evaluator has to remember. One evaluator forgetting it is a false PASS, and the Cycle 018 post-merge review found exactly that shape: a check that was correct everywhere it was written and absent from one path.

**Three separate taxonomies, deliberately not collapsed.**

- `TrustClass`: `SelfDeclared < Declared < Approved`, ordered so promotion is arithmetic and `may_establish_authority()` is true only at `Approved`.
- `VerificationStatus`: `is_recorded_evidence()` (a status was recorded) is a different question from `may_be_relied_on()` (the status is favourable). `a_recorded_verification_is_not_the_same_as_a_favourable_one` asserts they cannot be conflated.
- `EvidenceSource`: where a claim came from.

**AC-35 — a valid signature is not an authorized signer.** These two facts live in different types and are checked separately: `VerificationStatus` answers whether a signature verified locally, `TrustPolicy::approves_signer` answers whether that signer was approved. `verification_status_and_trust_stay_separate_questions` asserts the separation.

**AC-36 — an unapproved signer can deterministically fail its invariant.** `approves_signer` returns a definite `false` for a named signer that matches nothing, distinct from the absent-policy case which returns a gap.

**AC-33 — builder trust is independent of provenance presence.** A provenance record exists or does not; its builder is approved or is not. `the_three_bindings_are_independent` in `provenance.rs` asserts each can hold while another fails.
