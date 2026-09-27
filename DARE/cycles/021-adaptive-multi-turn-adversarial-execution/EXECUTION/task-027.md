# task-027 — Implement MULTITURN-LAB harness contract test

**Status:** DONE  
**Complexity:** MED

## Files changed

- `crates/dare-multi-turn-security/tests/multiturn_lab.rs` (new)

## Tests

- `the_corpus_has_at_least_forty_entries_with_unique_ids` (45, numbered contiguously)
- `every_attack_theme_has_a_control`
- `every_invariant_has_an_attack_and_a_control`
- `every_entry_meets_its_class_contract_in_every_staged_mode`:
  - ATTACK→FAIL, with its own invariant failing and deciding turns present;
  - CONTROL→PASS;
  - GAP→INCONCLUSIVE;
  - FAULT→ERROR;
  - REFUSAL refused.

  Agent entries run in SIMULATED and LOCAL_SYNTHETIC; transcript entries run in REPLAY.
- `recorded_simulated_runs_replay_to_the_same_verdict`: every agent-driven entry is recorded through `RecordingAdapter` and replayed. The verdict, path and chain digests are identical, and only the `synthetic` flag differs.
- `no_fixture_states_its_own_outcome`
- `no_pass_is_ever_produced_for_a_gap_or_fault_in_any_mode`

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 3939 passed, 0 failed
- Audit: no dependency change
