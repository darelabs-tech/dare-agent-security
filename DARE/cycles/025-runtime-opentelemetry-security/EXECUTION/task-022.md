# task-022 — Add the `validate runtime-telemetry` CLI subcommand

**Status:** DONE  
**Complexity:** MED

## Engine: `src/render.rs`

`artifacts(run, policy)` builds the four RF-14 artifacts in memory, in this fixed
order:

1. **`runtime-telemetry-result.json`**: the result, after its evidence ids are bound.
   It is checked against `result.schema.json`, and a failure is an internal error.
2. **`runtime-telemetry-evidence.json`**: `{schema_version, engine, records, executions,
   coverage}`.
   - `records`: the Cycle 001 `SecurityEvidence` records.
   - `executions`: the passive `TRACE` `ExecutionsDocument`, checked against the run's
     facts.
   - `coverage`: the Cycle 006 report over `runtime-telemetry-baseline-2026`.
3. **`runtime-telemetry-findings.json`**: one entry per FAIL or INCONCLUSIVE trace
   outcome.
   - Each entry has the rule code, property id, trace id and verdict.
   - Each violation has its `reason_code`, span ids, keys (through `safe_key`) and value
     fingerprints (BLUEPRINT §4.2).
   - Each gap is listed, and a `missing_key` gap goes through `safe_key`.
4. **`summary.md`**.

## CLI: `crates/dare-agent-security-cli/src/runtime_telemetry.rs`

The flags follow BLUEPRINT §4.4:
- `--traces <FILE>` (repeatable, 1–64);
- `--policy <FILE>`;
- `--output-dir <DIR>`;
- `--max-spans N` (default 1 000 000; only lowers it; 0 and anything above are
  refused);
- `--json`.

There is no `--mode` flag: CLI runs are always REPLAY.

The order of operations is:
1. validate the output directory;
2. check the bounds;
3. load the embedded mapping;
4. load the policy;
5. admit the traces (by position);
6. analyse;
7. render the four artifacts;
8. sweep **every** artifact with `dare_attack_graph::v2::sweep::is_sensitive`, before
   any write (a hit is `UnsafeArtifact`, exit 3);
9. create the directory and write.

**Exit codes (BQ-5):**
- 0: the run verdict is PASS;
- 2: FAIL or INCONCLUSIVE, including `nothing_judged`;
- 3: a refusal;
- 1: an internal error.

`after_help` states the exit codes and what is not claimed. The subcommand is wired in
`args.rs`, `main.rs` and `lib.rs`, and the CLI gains the one dependency
`dare-runtime-telemetry`, which is the only dependent the crate's manifest test allows.

## Tests: `crates/dare-agent-security-cli/tests/runtime_telemetry_cli.rs` (6)

- `help_names_every_flag_and_offers_no_network_or_exec_flag`: the flag set is exactly
  the six flags. `--endpoint`, `--listen`, `--port`, `--collector`, `--otlp-endpoint`,
  `--header`, `--token`, `--exec` and `--mode` are each rejected and none is offered.
- `exit_0_writes_the_four_files_when_every_judged_property_passes`: the evidence records
  validate as Cycle 001, the executions are `TRACE`, and the coverage profile is
  `runtime-telemetry-baseline-2026`.
- `exit_2_on_a_violation_or_when_nothing_can_be_judged`: a B-1 FAIL finding, and an empty
  export giving `INCONCLUSIVE (nothing_judged)`.
- `exit_3_on_a_refusal_writes_nothing`: a doctored trace (by position), an invalid
  policy, `--max-spans 0`, `--max-spans` above the maximum, and a missing file. None
  writes anything, and stderr names the position, never the path or the content.
- `exit_1_on_an_internal_write_failure`
- `no_attribute_value_reaches_any_file_or_stdout`: canary values, a header value, the
  principal, the tool and the agent name are absent from all four files, stdout and
  stderr.

## Ralph Loop

| Step | Result |
|---|---|
| Build | ok |
| Test | `runtime_telemetry_cli` 6/6; `dare-runtime-telemetry` manifest 3/3 (only the CLI depends on the crate); full `dare-agent-security` suite with `--no-fail-fast`: no failure (after `cargo build --workspace --bins`, which `discover_cli` needs for `synthetic-mcp`) |
| Lint | fmt; clippy `-D warnings` on `dare-runtime-telemetry` and `dare-agent-security` (`--all-targets`): clean |
| Audit | No new package: the CLI gains only the workspace crate `dare-runtime-telemetry` |

During the task the disk filled up (the debug `target/` had grown to 24 GB). It was
cleared, and builds now use `CARGO_INCREMENTAL=0`.
