# task-050 — Implement `validate a2a` CLI with local-safe flags only

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Expose the engine as `dare-agent-security validate a2a`, with a flag surface that makes the offline boundary unreachable rather than merely undocumented.

## Files changed

- `crates/dare-agent-security-cli/src/a2a_security.rs` (new, 11 tests)
- `crates/dare-agent-security-cli/src/args.rs`, `lib.rs`, `main.rs`, `Cargo.toml`
- `crates/dare-a2a-security/src/budget.rs` (`AdmissionLedger::with_ceilings`, 3 tests)

## The flag surface is the security boundary

Nine flags, each a local path, a mode, a limit or an output location:

`--scenario`, `--mode`, `--evidence-dir`, `--capture`, `--policy`, `--max-peers`, `--max-exchanges`, `--output-dir`, `--json`.

The sixteen forbidden flags — `--endpoint`, `--url`, `--token`, `--api-key`, `--client-secret`, `--username`, `--password`, `--private-key`, `--certificate`, `--login`, `--jwks-url`, `--webhook-test`, `--command`, `--shell`, `--download`, `--fetch` — are asserted absent two ways:

1. `the_help_offers_no_flag_that_could_reach_a_peer` renders the actual long help and fails if one appears.
2. The same test then *parses* each one and asserts the parse fails. Undocumented is not the same as unavailable, and a flag that parses means a code path able to use it — which is the thing that must not exist.

`every_flag_the_help_offers_names_a_path_a_mode_a_limit_or_an_output` is the inverse: it walks every `--flag` token in the rendered help against an allow-list. A *new* flag outside the four permitted categories fails there even though nobody thought to ban it by name, which is the failure mode a ban list alone cannot catch.

## The two limit flags can only tighten

`AdmissionLedger::with_ceilings` clamps to `HARD_MAX_PEERS` and `HARD_MAX_EXCHANGES` and never above. A flag that could raise a hard bound is not a limit, it is a bypass, and the point of a hard bound is that no invocation can argue with it. `a_ceiling_flag_can_only_tighten` passes `u32::MAX` and asserts the hard maximum comes back.

A ceiling of zero is refused rather than clamped: zero would admit nothing and then report a clean run over an empty analysis, which is the shape of answer this engine exists not to give.

A tightened ceiling *refuses* rather than truncating. Truncation would produce a partial analysis reported as a complete one, which is worse than refusing to start.

## Replay may not supply its own policy

`--mode replay` requires `--policy` and says why in the error: a capture is evidence about what happened, not an approval, and one that could carry the policy it is judged against would let a recorded run declare its own approvals. `replay_requires_a_policy_the_capture_did_not_supply` pins the requirement and the message.

A flag belonging to another mode is refused rather than ignored. Silently ignoring `--evidence-dir` under `--mode simulated` would let an operator believe a capture was read when the run staged a fixture instead.

## Six artifacts, every byte charged

`a2a-peers.json`, `a2a-exchanges.json`, `a2a-findings.json`, `a2a-evidence.json`, `summary.md`, then `a2a-result.json` last.

The order matters: the result is written last so its budget snapshot includes every retained artifact. `serialize_result_with_final_budget` then loops to a fixed point, because writing `output_bytes_used` into the artifact changes the artifact's length by a few digits, which changes the budget again. `a_run_writes_all_six_artifacts_and_charges_every_byte` reads the written file back and asserts `output_bytes_used >= file length` — the Cycle 019 post-merge correction, which found the budget bounding everything except the largest thing the run produced.

`the_findings_artifact_exists_and_is_an_array_even_when_clean` covers the other Cycle 019 lesson: a CI check counting findings needs a file to count, and an absent file is not a count of zero.

## No artifact leaves carrying a credential

`assert_bytes_are_secret_safe` runs over every artifact before it is written, and uses `contains_bearer_credential` — anchored on shape, so this engine's own prose about bearer tokens stays writable while a real value is refused. `no_artifact_is_written_that_carries_a_credential` pins all four cases, including the honest sentence that must stay allowed.

## The help states the claim boundary

`the_help_states_the_offline_boundary_and_the_bounded_claim` asserts three sentences survive editing: "never re-sends traffic", "stays inert metadata", and "not a statement that a remote agent is secure". An operator who reads only `--help` must still learn what a PASS covers.

## Commands executed

```
cargo test -p dare-agent-security --lib a2a_security::
cargo test -p dare-agent-security
cargo test -p dare-a2a-security --lib budget::
cargo clippy -p dare-agent-security --all-targets -- -D warnings
cargo fmt --all
```

## Result

11 CLI tests and 13 budget tests passing; the whole `dare-agent-security` CLI crate green across 30 binaries; clippy clean.

## Evidence

```
cargo test -p dare-agent-security --lib a2a_security::
test result: ok. 11 passed; 0 failed; 0 ignored
```

## Review result

**REVIEW PASS**
