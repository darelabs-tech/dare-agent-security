# task-017 — Implement Cycle 009-gated `LocalSyntheticAdapter`

**Status:** DONE  
**Complexity:** MED

## Files changed

- `crates/dare-multi-turn-security/src/local_synthetic.rs` (new)

## Result

Before every turn, the adapter builds a read-only `VectorStep`: `SYNTHETIC_NOOP`, zero
writes, zero state changes, zero egress, identifiers only, and target
`synthetic-multi-turn-agent`. The step then goes through Cycle 009
`kill_switch::inspect_step`, `BudgetState::check_next` and `consume`. Outcomes:
- a triggered control: `CONTROL_TRIGGERED` (ERROR);
- budget exhaustion: `BUDGET_EXHAUSTED` (INCONCLUSIVE).

The control snapshot is recorded for evidence.

## Recorded choice

Cycle 009's `BudgetState` also stops on wall-clock duration. The duration is set to
300 s, far above any legitimate run, so that it acts as a kill bound only and never
decides a normal run's outcome. Determinism tests (task-034) run far below it.

## Tests (`local_synthetic::tests`)

- `every_turn_passes_the_cycle_009_controls_and_changes_nothing` (snapshot shows 0 state changes and 0 egress)
- `a_substituted_target_trips_the_kill_switch`
- `the_budget_stops_the_next_turn_as_budget_exhausted`
- `the_budget_allows_no_write_state_change_or_egress`
- `the_step_carries_identifiers_only`

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 3858 passed, 0 failed
- Audit: no dependency change
