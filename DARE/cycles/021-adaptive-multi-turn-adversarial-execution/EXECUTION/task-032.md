# task-032 — Add `validate multi-turn` CLI subcommand

**Status:** DONE  
**Complexity:** MED

## Files changed

- `crates/dare-agent-security-cli/src/multi_turn_security.rs` (new)
- `crates/dare-agent-security-cli/src/{args.rs,main.rs,lib.rs}`: `validate multi-turn` registered
- `crates/dare-agent-security-cli/Cargo.toml`: path dependency
- `crates/dare-multi-turn-security/src/result.rs`: `render_artifacts` takes extra artifacts (the evidence file), so every artifact is admitted before any is written; `json_bytes` is made public

## Result

The flags are `--scenario` (a corpus id or a file), `--graph` (1–4), `--transcript`,
`--mode`, `--max-turns` (clap range 1–32), `--max-paths` (1–64), `--output-dir` and
`--json`.

The exit codes are:
- 0: PASS;
- 2: FAIL or INCONCLUSIVE;
- 1: ERROR;
- 3: usage error or refusal, with nothing written.

All five artifacts are serialized and admitted before the first write. The evidence
artifact carries the Cycle 001 records plus the Cycle 006 coverage report.

## Deviation recorded

The Blueprint's flag table would let a scenario *file* run in SIMULATED mode, but the
simulated agents are lab reference behaviours, and choosing one would need a
`--reference-agent` flag. That flag would let a real scenario be labelled with a
synthetic behaviour. Therefore:
- SIMULATED and LOCAL_SYNTHETIC run **MULTITURN-LAB corpus ids only**;
- a scenario file runs in REPLAY over a supplied transcript.

The Blueprint examples (`multiturn-lab-003` exit 2, `multiturn-lab-001` local-synthetic
exit 0) behave as specified.

## Tests (`multi_turn_security::tests`)

- `the_help_offers_no_flag_that_could_reach_or_generate`: 16 forbidden flags, each absent from the help **and** failing to parse
- `bounds_above_the_hard_maxima_do_not_parse`
- `a_control_passes_and_writes_every_artifact`: exit 0, all 5 files present
- `an_attack_exits_two_in_local_synthetic_mode`
- `a_harness_fault_exits_one`
- `refusals_exit_three_and_write_nothing`: cycle graph, unknown id, wrong mode, path traversal, `../escape` output
- `lowered_bounds_that_the_graph_exceeds_are_a_refusal`
- `scenario_files_replay_over_a_local_transcript`: lab-027 exported to files gives exit 2, FAIL, `synthetic=false`
- `a_scenario_file_cannot_be_run_by_a_simulated_agent`

A manual run of the real binary (`cargo run -- validate multi-turn --scenario multiturn-lab-002`)
exited 2, wrote all five artifacts, and its `summary.md` shows the path taken and the
unreached nodes.

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 3955 passed, 0 failed
- CI job: `python scripts/run-ci-job-locally.py .github/workflows/ci.yml multi-turn-security-2026`: **all 12 steps PASSED**
- Audit: no external dependency change (`dare-multi-turn-security` added as a path dependency of the CLI)
