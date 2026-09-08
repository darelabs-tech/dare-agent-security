# task-043 — Build missing-evidence INCONCLUSIVE and multi-violation regressions

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-50, AC-51, AC-52, AC-53, AC-54, AC-68

## Evidence

`src/corpus.rs` (the forty entries) and `crates/dare-supply-chain-security/tests/supply_lab.rs` (the harness contract).

## The split that makes the corpus worth having

An entry records a **class** — `CONTROL`, `ATTACK`, `REFUSAL`, `GAP` — and never a verdict. There is no `expected_verdict`, no `expected_findings`, no `is_secure`. `no_entry_declares_an_outcome_anywhere_in_its_evidence` asserts none of those strings reaches the evaluator from any of the forty bundles.

The expectation lives in the harness contract instead, asserted once per class rather than per fixture:

- **ATTACK** — the declared invariant must report `FAIL`, and every violation must cite deciding evidence.
- **CONTROL** — nothing may `FAIL`, and the declared invariant must reach `PASS`.
- **REFUSAL** — the bundle must be refused before evaluation, and the refusal must not echo what it refused.
- **GAP** — the declared invariant must be `INCONCLUSIVE`: never `PASS`, and never `FAIL` either, because thin evidence is not a finding.

## The gap entries

`every_gap_is_undecidable_rather_than_passing_or_failing` covers entries 012, 022 and 025 and asserts `INCONCLUSIVE` with `coverage_satisfied: false` for each. Never `PASS`, and never `FAIL` either: thin evidence is not a finding, and reporting it as one would train an operator to dismiss real findings alongside it.

## The false PASS this corpus found

Entries 022 and 025 both reported **PASS** when they were first run.

The coverage contracts checked that the required channel was *present*. A capability context is emitted as soon as **either** side supplies capabilities, and a lineage context is emitted for **every** model whether or not a base was observed — so both invariants found the channel they needed, found no violation, and passed having compared nothing.

That is the same false PASS the contracts exist to prevent, one level in. `assess_coverage` now runs a second step, `comparison_reason`, which asks whether the comparison was actually made: drift needs `drifted().is_some()`, lineage and dataset provenance need `is_decidable()`, integrity needs an approved digest to compare against, provenance and attestation binding need a bound subject digest, dependency integrity needs `comparable`, and source trust needs a policy answer.

`a_present_channel_that_compared_nothing_does_not_satisfy_a_contract` asserts the new step directly.

Three invariants are deliberately exempt — identity ambiguity, mutable-reference identity and BOM completeness decide from the component set alone, and there is no approved side that could be missing.

## Multi-violation retention

**AC-68.** `the_multi_violation_entry_retains_every_independent_finding` stages entry 036 — a bundle that substitutes a digest, comes from an unapproved vendor and drifts a capability — and asserts violations from all three invariants are retained. One bundle crossing three boundaries must report three, or a run understates what it saw and an operator fixes one of them.

**AC-52/AC-53** are asserted in `invariant.rs` by `every_applicable_invariant_is_evaluated_regardless_of_which_one_a_fixture_targets`, and **AC-54** by `a_secondary_gap_does_not_erase_a_primary_failure`.

## Two corpus-wide regressions

**Determinism.** `staging_is_deterministic_for_every_entry` builds every entry twice and compares canonical digests, requiring that an entry which refuses refuses both times. A corpus that staged differently between runs would produce reports that differ from themselves.

**Nothing is untested.** `every_invariant_is_exercised_by_at_least_one_entry` asserts all twelve invariants are behind at least one entry. An invariant with no fixture behind it is an untested claim in the report, and it looks exactly like a covered one.
