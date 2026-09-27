# task-019 — Implement conversation runner and stop reasons

**Status:** DONE  
**Complexity:** HIGH

## Files changed

- `crates/dare-multi-turn-security/src/runner.rs` (new)

## Result

`run_conversations` validates the scenario, then for each conversation starts at the
root and repeats: admit the turn, respond, normalize, charge evidence, push, then stop
or follow the declared edge. Every `StopReason` is reachable. A replayed
`chain_digest` that disagrees with the recomputed chain is refused as
`TranscriptTampered` (no result). `unreached_nodes` is recorded per conversation, and
`finish` faults are carried as `finish_fault`.

A harness `BUDGET_EXHAUSTED` from the adapter ends the run without recording a turn
(the turn did not happen). Every other harness error is recorded as a harness-error turn.

## Tests (`runner::tests`)

- `a_secure_agent_walks_the_refusal_path_to_the_terminal`
- `the_observation_selects_the_next_node`
- `stop_on_first_fail_stops_at_the_deciding_turn`
- `a_missing_edge_stops_with_no_transition`
- `harness_failure_ambiguity_and_budget_each_have_their_stop_reason`
- `every_executed_turn_is_a_graph_node_reached_by_a_declared_edge` (I08 for simulated runs)
- `a_faithful_replay_reaches_the_terminal_and_a_short_one_is_a_strategy_fault`
- `a_recorded_chain_digest_that_disagrees_is_refused_as_tampering`
- `a_scenario_that_does_not_validate_is_refused_before_any_turn`

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
