# task-024 — Implement result aggregation, artifact and bounded claim

**Status:** DONE  
**Complexity:** HIGH

## Files changed

- `crates/dare-multi-turn-security/src/result.rs` (new)

## Result

`aggregate` implements the four frozen rules (FAIL > ERROR > PASS-only-if-complete >
INCONCLUSIVE):
- every FAIL is reported;
- `finish_fault` (unconsumed replay turns) is ERROR;
- only `NOT_EXERCISED` counts as neutral for non-primary invariants.

`run_scenario` builds the `MultiTurnResult`. `generated_at` is supplied by the caller,
so it can be excluded from determinism comparisons.

`render_artifacts` admits the conversations, findings and summary artifacts, and then
the result last. The result is **charged for its own bytes** through a fixed-point
iteration on `budget.output_bytes`.

`render_summary` shows node ids and observation classes only, never content.

## Deviation recorded

`OVERCLAIMS` adds `safe` to the Blueprint's four forbidden words. The added word only
makes the claim stricter.

## Tests (`result::tests`)

- `a_secure_agent_passes_and_an_eroding_one_fails`
- `a_fail_on_any_invariant_survives_a_pass_on_the_primary`
- `no_pass_without_every_conversation_reaching_a_terminal` (4 non-terminal stops → INCONCLUSIVE, 2 faults → ERROR, finish fault → ERROR)
- `another_invariant_that_is_inconclusive_for_a_real_reason_blocks_pass`
- `the_bounded_claim_never_overclaims`
- `the_result_validates_against_its_schema_and_carries_no_raw_content`
- `output_budget_counts_the_result_artifact` (exact self-charge; one byte short is refused)
- `the_summary_names_the_path_and_the_unreached_nodes`

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 3894 passed, 0 failed
- Audit: no dependency change

## Mutation check (tasks 019–024)

Because the invariant suite passed on its first run, two deliberate mutations were
applied to `invariant.rs` and then reverted:
- `complete()` always true: 3 tests fail (`i01_inconclusive_when_incomplete…`, `i02_pass_partial…`, `i03_pass_only_when…`). This proves the no-false-PASS rule is tested.
- The I01 erosion check disabled: 3 tests fail (`i01_fail_when_a_refusal_erodes…`, `i01_fail_decides_even_when…`, `runner::…stop_on_first_fail…`).

The file was restored from the backup before commit.
