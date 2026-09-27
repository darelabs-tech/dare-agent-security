# task-014 — Define `ConversationAdapter` trait, `HarnessMode` and `RawHarnessError`

**Status:** DONE  
**Complexity:** LOW

## Files changed

- `crates/dare-multi-turn-security/src/harness.rs` (new)
- `crates/dare-multi-turn-security/src/observation.rs`: `HarnessErrorKind::BudgetExhausted`
- `schemas/multi-turn-security/v1/transcript.schema.json`: enum updated to match

## Result

The trait uses the Blueprint §4.9 signature (`mode`, `respond(&ConversationState,
&StrategyNode)`) plus three default methods:
- `finish`: replay reports unconsumed turns;
- `recorded_chain_digest`: the runner checks transcript tampering;
- `control_snapshot`: local-synthetic evidence.

`HarnessMode` lives in `model.rs` (task-008).

## Deviation recorded

The Blueprint says that a Cycle 009 budget exhaustion becomes
`StopReason::BudgetExhausted` but gives the adapter no way to signal it. A fifth harness
error kind, `BUDGET_EXHAUSTED`, carries that signal. The runner maps it to
INCONCLUSIVE rather than ERROR. It can never produce PASS.

## Tests

The trait is exercised by the adapter tests in tasks 015–017. The enum serialization is
covered by `schema::tests::the_embedded_copies_equal_the_files_on_disk`.

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 3858 passed, 0 failed
- Audit: no dependency change
