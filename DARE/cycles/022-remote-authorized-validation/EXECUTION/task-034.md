# task-034 — Implement `run_remote` and `replay_capture`

**Status:** DONE (signature extended; recorded)  
**Complexity:** HIGH

## Result (`runner.rs`)

**`run_remote`**, in order:
1. `verify` checks all 16 rules. Rule 14 uses `EngineDigests`, which is each engine's own digest of the scenario it would run. A multi-turn run whose graph digests differ can never match.
2. Every run is loaded and checked against the plan protocol. Prompt injection runs only over `DARE_CONVERSATION`, multi-turn over `DARE_CONVERSATION` or A2A, A2A over A2A, and MCP Auth over MCP.
3. A2A policy files are resolved under `--policy-dir`. A plain `*-policy.json` name is required, canonicalized, and must stay under the directory.
4. One gateway runs each live pass in order.
   - A stop (budget, kill, window, egress refusal) ends the live pass without being an error.
   - With `stop_on_first_fail`, each scenario's engine verdict is checked over a capture snapshot, and a FAIL records `FIRST_FAIL`.
5. The verdict pass (`decide`) runs over the finished capture.

**`replay_capture`** opens no socket, and needs no credential and no open window. It
checks, in order:
- the capture chain;
- the audit chain against the capture;
- that the authorization, plan and origin digests match the capture;
- that every scenario still has its authorized digest.

It then runs the same `decide`, so the results are byte-identical (O-03).

**`engines::unfinished`** now distinguishes `FIRST_FAIL`: the failing scenario finished,
and later ones never ran.

## Signature extension (recorded in REGRESSION.md)

BLUEPRINT §5.2 did not provide where the engines' scenario files live, or where A2A's
scratch documents go. Both entry points gained `sources: &Sources` and
`work_root: &Path`. The scratch directory is `<work_root>/.remote-work/<capture_id>/`,
and it is removed after the verdict pass.

`run_with_gateway` (lab and test only) accepts a pre-built gateway for injected
resolvers.

## Tests (`tests/runner.rs`)

- `a_live_run_and_its_replay_are_byte_identical_and_the_artifacts_are_clean`: `multiturn-lab-002` gives FAIL, the same as offline.
  - The replayed result **and** evidence are byte-identical.
  - The result, capture and audit validate against their schemas.
  - There are exactly five artifacts, and none contains the token.
  - All evidence is `PROTOCOL_RESPONSE` and valid.
  - The summary carries the verdict and the bounded claim.
- `a_pass_says_which_target_reported_fields_it_relies_on`: `multiturn-lab-001` gives PASS with `refusal` marked, in the summary as well.
- `after_a_first_failure_later_scenarios_are_never_sent`: `PI-LAB-002` FAILs and the run stops with `FIRST_FAIL`. `multiturn-lab-001` is INCONCLUSIVE with 0 exchanges, and the replay is identical.
- `a_budget_stop_leaves_the_running_scenario_inconclusive_never_pass`: `max_requests: 2` gives exactly 2 hits, `BUDGET_EXHAUSTED`, and no PASS.
- `replay_refuses_a_tampered_capture_and_a_foreign_authorization`: `CaptureTampered(0)`, then `Refused`.
- `a_refused_authorization_sends_nothing`: a wrong scenario digest gives `Authorization(..)` and 0 hits.

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation`: 179 passed
