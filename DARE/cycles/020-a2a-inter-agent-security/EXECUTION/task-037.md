# task-037 — Implement deterministic cross-invariant aggregation preserving Cycle 018 semantics

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Combine fourteen outcomes into one verdict without losing the worst of them.

## Files changed

- `crates/dare-a2a-security/src/invariant.rs` (`aggregate`, `evaluate_all`, `collect_observed_violations`, `applies_to`)

## Precedence, unchanged from Cycle 018

FAIL > ERROR > INCONCLUSIVE > PASS. One concrete failure outranks thirteen undecided answers, because a run that averaged its outcomes would hide a FAIL behind them. `a_secondary_gap_does_not_erase_a_primary_failure` and `a_failure_outranks_a_later_harness_error` hold the two orderings that are easiest to get backwards.

`coverage_gates_pass_and_never_gates_fail` is the other half: coverage can stop a PASS, and must never turn a FAIL into an INCONCLUSIVE. Evidence good enough to show a crossing is good enough to report it.

## Every applicable invariant is evaluated, not just the targeted one

`every_applicable_invariant_is_evaluated_regardless_of_which_one_a_fixture_targets` asserts a scenario's `primary_invariant` is a coverage selector and not a filter. A bundle staged to exercise I09 that also crosses I06 reports both.

## The Cycle 019 correction: `applicable`

`A2aInvariantOutcome::applicable` is distinct from `coverage_satisfied`. Coverage asks whether an invariant that *does* apply could be decided; applicability asks whether it has a subject at all. A run with a repeated transfer and no idempotency evidence is applicable and undecided; a run with no repeats is neither, and `aggregate` ignores the inapplicable.

Without this, a fully compliant exchange reported INCONCLUSIVE because it registered no push notification — found by the first local CI run in Cycle 019, and built in here from the start. `an_invariant_with_no_subject_is_inapplicable_rather_than_undecided` pins it.

## No inference from prose

`no_violation_reads_as_prose_inference` asserts every violation is produced by a structured comparison rather than by matching text. `the_fourteen_evaluators_are_all_reachable` asserts none of the fourteen is dead code — an evaluator nobody can reach is an invariant nobody checks, reported as satisfied.

## Commands executed

```
cargo test -p dare-a2a-security --lib invariant::
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

24 tests passing.

## Evidence

```
cargo test -p dare-a2a-security --lib invariant::
test result: ok. 24 passed; 0 failed
```

## Review result

**REVIEW PASS**
