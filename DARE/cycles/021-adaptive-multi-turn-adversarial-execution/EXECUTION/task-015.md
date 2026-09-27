# task-015 — Implement `ReplayAdapter` with strategy-integrity (I08) and tamper checks

**Status:** DONE  
**Complexity:** HIGH

## Files changed

- `crates/dare-multi-turn-security/src/replay.rs` (new)

## Result

`ReplayAdapter::new` binds a transcript to a scenario. The transcript's
`graph_digests` must equal the scenario's pinned digests, and conversations must not
repeat.

`respond` returns a recorded turn only when both its index and its node match the
runner's selection. The following are `STRATEGY_FAULT` (I08 → ERROR):
- a reordered, inserted or wrong-node turn;
- a turn missing from the transcript (dropped);
- a turn left unconsumed after the run (reported by `finish`).

A recorded `chain_digest` is exposed for the runner's tamper check. The
`TranscriptTampered` refusal is raised in the runner (task-019), where the recomputed
chain exists.

## Tests (`replay::tests`)

- `a_faithful_transcript_replays_and_is_fully_consumed`
- `a_turn_for_a_different_node_is_a_strategy_fault`
- `reordered_and_inserted_turns_are_strategy_faults`
- `a_dropped_turn_is_a_strategy_fault`
- `unconsumed_turns_are_a_strategy_fault`
- `a_transcript_for_other_graphs_is_refused_at_binding`

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 3858 passed, 0 failed
- Audit: no dependency change
