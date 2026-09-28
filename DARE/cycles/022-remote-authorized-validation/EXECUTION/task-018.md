# task-018 — Implement `RateLimiter`, the budget wrapper over `BudgetState` and `RemoteKillSwitch`

**Status:** DONE  
**Complexity:** MED

## Result (`control.rs`)

- **`RateLimiter`.** Minimum spacing of `1000 ms / max_rps`. A slot at or after the deadline is refused without sleeping.
- **`RemoteBudget`.** It wraps Cycle 009 `BudgetState` with an `ExecutionBudget` derived from the effective limits:
  - state changes and retries are 0;
  - egress and written bytes are `requests × request bytes`.

  `check_next` stays authoritative. The refusal names requests, bytes or duration from the snapshot, because the Cycle 009 message is generic.
- **`RemoteKillSwitch`.**
  - It latches the first trigger.
  - `observe_status` triggers `TargetInstability` on the third consecutive `429`/`5xx`, or on the first one when the plan stops on its first failure.
  - It triggers `UnexpectedTarget` on any `3xx`.
  - `SecretDetected`, `UnexpectedIdentity` and `OperatorStop` are raised by the gateway through `trigger`.

## Tests

- `spacing_is_exactly_the_interval` (paused clock: 0/500/1000/1500 ms)
- `a_slot_past_the_deadline_is_refused_without_sleeping`
- `the_budget_is_derived_from_the_limits`
- `the_request_after_the_last_allowed_one_is_refused`
- `a_step_never_declares_a_state_change`
- `kill_triggers_latch_and_block_the_next_send`
- `instability_triggers_after_three_or_on_first_fail`
- `a_redirect_status_triggers_unexpected_target`

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation`: 103 passed
- No external dependency added
