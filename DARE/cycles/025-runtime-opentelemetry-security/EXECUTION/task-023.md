# task-023 — Add the CLI refusal corpus and the double-run test

**Status:** DONE  
**Complexity:** MED

## `crates/dare-agent-security-cli/tests/runtime_telemetry_refusals.rs` (7 tests)

For every case, `assert_refused` checks that:
- the command exits 3 and **no output directory exists**;
- stderr starts with `refused: ` and contains the expected reason, so a case cannot
  pass through an unrelated refusal;
- neither stdout nor stderr contains the planted `CANARY-REFUSAL-4c1d8e`, a `/tmp` path
  or a `.json` file name.

| Test | Cases (expected reason) |
|---|---|
| `every_trace_admission_refusal_exits_3_and_writes_nothing` | missing file (`trace file 1 cannot be read`); directory; symlink to a valid file; 65 files; 16 MiB + 1 file; JSON 65 levels deep; invalid UTF-8; not JSON |
| `the_total_size_limit_is_enforced_across_files` | 17 × 15.5 MiB, each admissible alone (`exceed the total size limit`) |
| `every_trace_content_refusal_exits_3` | unknown top-level field; enum name for `kind`; short trace id; all-zero span id; non-hex id; non-numeric time; `resourceSpans` not an array. Each is refused as `trace file 1 is not valid OTLP/JSON`, by position, after a valid file 0 |
| `every_policy_refusal_exits_3` | missing field, unknown field, schema version, bad policy id, unknown operation (`(schema)`); a well-formed key off the principal allow-list (`(principal_key)`, AD-09); policy over 1 MiB; not JSON; symlink |
| `bound_and_output_directory_refusals_exit_3` | `--max-spans 0` and `1000001`; an output directory with `..` |
| `an_artifact_that_fails_the_output_sweep_is_never_written` | a `policy_id` of `sk-live-…` passes the policy schema but would be written into the result. The sweep refuses before the first write, naming the file and not the value |
| `two_runs_give_byte_identical_files_whatever_the_file_order` | two runs over two exports (one failing) in opposite `--traces` order give four byte-identical files |

**Not reachable from the CLI:** `NoTraceFiles`, because clap requires `--traces`. That
is a usage error, and the empty-list refusal is covered in the crate
(`result.rs::a_file_outside_the_trace_schema_is_refused_by_position`).

## Ralph Loop

| Step | Result |
|---|---|
| Build | ok |
| Test | `runtime_telemetry_refusals` 7/7, about 17 s (the size cases write about 280 MB into a temp dir) |
| Lint | fmt; clippy `-D warnings --all-targets` on `dare-agent-security`: clean |
| Audit | No dependency change |
