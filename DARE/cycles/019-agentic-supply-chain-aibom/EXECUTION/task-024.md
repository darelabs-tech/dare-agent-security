# task-024 — Define invariant-specific positive PASS/INCONCLUSIVE contracts

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-50, AC-51

## Evidence

`src/coverage.rs`.

**AC-50 — PASS requires positive, invariant-specific evidence.** Every invariant declares the channels a run must have produced before it may report PASS. Without this an invariant would pass whenever nothing contradicted it.

That failure mode is concrete here rather than theoretical: **the cheapest way to make every supply-chain check pass is to hand the engine an empty bill of materials.** No components, no digests, nothing to disagree with. `an_empty_run_satisfies_no_contract` asserts all twelve contracts refuse it.

**AC-51 — a missing deciding channel yields INCONCLUSIVE, never PASS.** `assess_coverage` returns the missing channels by name, and `a_missing_channel_is_named_in_the_reason` asserts the name reaches the operator-facing text. An operator handed "INCONCLUSIVE" learns nothing; one handed `PROVENANCE_CONTEXT` knows what to collect next.

## Comparison channels

Some invariants need two sides, not one. Seeing a component's digest proves nothing about whether it is the approved artifact unless something recorded which artifact was approved.

`COMPARISON_CHANNELS` marks the five channels that carry an approved side. `the_comparison_invariants_are_the_ones_that_need_an_approved_side` asserts that drift, provenance, attestation, lineage and dataset provenance all require one, and that identity ambiguity does **not** — marking it as a comparison would make a legitimate PASS impossible without a manifest, and identity ambiguity is a property of the component set rather than a comparison against an approval.

## Contracts that would have been wrong

**Completeness requires the document.** `completeness_cannot_pass_without_a_document_having_been_read`. A run that assembled components in memory and read no bill of materials has not assessed a bill of materials' completeness.

**Digest-deciding invariants require the digest channel.** `digest_bearing_invariants_require_the_digest_channel` — integrity, provenance binding and attestation binding all decide against an artifact digest. Requiring only the record would let each of them pass on a component nobody could identify.

**A run with only an inventory covers only the identity invariants.** `a_run_with_components_alone_covers_only_the_identity_invariants` asserts the boundary in both directions: identity and mutable-reference pass; provenance, attestation, lineage and drift do not.

## Coverage never claims an outcome

`a_satisfied_contract_says_so_without_claiming_a_verdict` — a coverage decision says the question was answerable, never what the answer was.
