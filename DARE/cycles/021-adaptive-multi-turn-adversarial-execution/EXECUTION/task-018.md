# task-018 — Implement `OutputLedger` (`admit_bytes`, `admit_turn`, `admit_output`)

**Status:** DONE  
**Complexity:** MED

## Files changed

- `crates/dare-multi-turn-security/src/budget.rs` (new)

## Result

`OutputLedger` implements the following. The Blueprint's `admit_bytes` is named
`admit_evidence`, because it charges retained evidence.
- `begin_conversation`;
- `admit_turn`, with the per-conversation bound;
- `admit_evidence`, charging retained evidence;
- `admit_output`, which charges before a write and charges nothing on refusal;
- `snapshot`, with state changes and egress always 0.

The result artifact's self-charge is wired in task-024.

## Tests (`budget::tests`)

- `the_turn_bound_is_per_conversation_and_counted_in_total`
- `over_budget_output_is_refused_and_not_charged`
- `evidence_is_bounded_by_the_same_ceiling`
- `the_snapshot_never_reports_state_change_or_egress`

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 3858 passed, 0 failed
- Audit: no dependency change
