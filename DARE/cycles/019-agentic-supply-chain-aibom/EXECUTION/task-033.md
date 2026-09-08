# task-033 — Implement cross-invariant concrete FAIL aggregation and stop semantics

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-52, AC-53, AC-54

## Evidence

`src/invariant.rs` — `evaluate_all`, `collect_observed_violations`, `aggregate`.

**AC-52 — the scenario's invariant is a coverage selector, never a filter.** `every_applicable_invariant_is_evaluated_regardless_of_which_one_a_fixture_targets` stages a bundle that substitutes a digest, drifts a capability and comes from an unapproved vendor at once, then asserts violations from all three invariants are retained.

A corpus built around one question would otherwise never notice the answer to a second, and a fixture author's focus would silently become the engine's field of view. This is the Cycle 018 lesson applied to a wider evidence surface.

**AC-53 — all same-trial concrete FAILs are retained.** `collect_observed_violations` walks all twelve evaluators and keeps every violation, rather than returning on the first. `stop_on_first_fail` can stop *later trials* only after this has run.

**AC-54 — a secondary gap does not erase a primary failure.** `a_secondary_gap_does_not_erase_a_primary_failure` builds a bundle that fails integrity while being undecidable on lineage, and asserts the aggregate is FAIL. Precedence is `FAIL > ERROR > INCONCLUSIVE > PASS`, documented at `aggregate`.

`a_failure_outranks_a_later_harness_error` asserts the first step: an observed violation is retained evidence, and a run that broke afterwards does not unsee it.

**Coverage gates PASS and never gates FAIL.** `coverage_gates_pass_and_never_gates_fail` removes the document from a bundle with a real substitution and asserts the FAIL survives with `coverage_satisfied: true`. If coverage gated FAIL, an attacker could hide a finding by removing an unrelated document — the inverse of the property the contracts exist for.

**Findings cite evidence and name things.** `no_outcome_or_violation_reads_as_prose_inference` asserts every violation reason contains a quoted concrete identifier and every violation cites at least one deciding observation digest. A reason that could have been written without looking at the evidence is the shape a model-generated verdict takes, and this engine has none.
