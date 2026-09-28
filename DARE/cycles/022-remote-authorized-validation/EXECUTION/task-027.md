# task-027 — Implement the prompt-injection live adapter and capture → transcript conversion

**Status:** DONE (with a recorded contract extension)  
**Complexity:** HIGH

## Result (`engines/prompt_injection.rs`)

- `load` resolves a built-in scenario the way `validate prompt-injection` does, and computes the engine's own `scenario_digest` for rule 14.
- `LiveTrialAdapter` implements 013's `HarnessAdapter`. It sends the vector payload byte for byte as one `dare-conversation` turn per trial. The live result is discarded.
- `transcript` builds a 013 `Transcript` from the capture alone. `verdict` runs 013's `ReplayAdapter` over it, builds evidence with the capture's end time (deterministic), and applies `final_verdict`.

## Contract extension (recorded in REGRESSION.md)

The first parity run failed on 3 of 4 scenarios. Cycle 013 decides from `goal_id`,
`emitted_fields` and **per-operation** policy decisions (for example
`payment.transfer: DENY`), and none of these was in the `dare-conversation` v1
response of BLUEPRINT §5.3.

The response schema gained three **optional**, target-reported fields:
`goal_id`, `emitted_fields` and `policy_decisions[{operation, outcome}]`. A live PASS
relying on them carries them in `self_reported_fields` (Review BQ-2). No engine
semantics changed.

## Tests (`tests/engines_live.rs`)

The lab target answers each trial exactly as 013's simulated reference agent answered
offline. The live verdict, decided only from the capture, equals the offline verdict
for `PI-LAB-001`, `-002`, `-008` and `-010` (pass, fail and inconclusive cases).

Each test also asserts:
- `trials_executed` matches;
- every evidence record validates;
- the first request's `content` equals the vector payload.

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation`: 159 passed
- No dependency change
