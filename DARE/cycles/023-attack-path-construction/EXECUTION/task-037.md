# task-037 — Add the `validate attack-paths` CLI subcommand

**Status:** DONE  
**Complexity:** MED

## Change

- `crates/dare-agent-security-cli/src/attack_paths.rs` adds the flags of BLUEPRINT §5.1:
  `--artifacts` (repeatable, required), `--system-model`, `--output-dir`,
  `--max-path-edges` (default 8), `--max-paths`, `--max-paths-per-pair` and `--json`.
  `after_help` states the exit codes, and states that CONTROLS_HELD is not "secure".
- **Writing.** The six files are rendered first, and every one of them is swept (AD-12)
  before anything is written: `projection-report.json`, `attack-graph.json`,
  `attack-paths.json`, `graph.mmd`, `graph.dot`, `summary.md`. After that they are
  written in that order.
- **Exit codes:**
  - 0 when every feasible path is CONTROLS_HELD (or there is none) and nothing was cut;
  - 2 when a path is CONTROL_FAILED or CONTROL_UNDECIDED, or enumeration was truncated
    (BQ-4);
  - 3 on any refusal;
  - 1 on an internal error.
- **`summary.md`** gives:
  - the control-state table;
  - up to 50 paths, with entry and target classes, evidence status and control state;
  - the chokepoints;
  - the enumeration counts;
  - "What this does not claim". It covers paths beyond `max_path_edges`, unstated
    relationships, and how many artifacts came from synthetic runs or authorized remote
    runs.

  It uses the same wire names as the JSON.
- **Registration.** The subcommand is registered in `args.rs` and `main.rs`, and the CLI
  depends on `dare-attack-path`, the only crate that does (BQ-3 (a)).
- **`validate attack-graph --facts`** is unchanged.

## Tests (`crates/dare-agent-security-cli/tests/attack_paths_cli.rs`)

- `help_names_the_bounds_and_offers_no_widening_flag`: no URL, shell, exec, command,
  engine, proxy, token or execute flag exists, and each is rejected.
- `exit_0_writes_six_files_when_nothing_is_failed_undecided_or_cut`, including `--json`.
- `exit_2_when_a_feasible_path_is_undecided_or_enumeration_is_cut`.
- `exit_1_on_an_internal_write_failure_before_any_file_is_written`: a directory stands where
  the first file must go, so the write fails even as root.
- `exit 3`: see task-038.
- `the_same_inputs_give_byte_identical_files`: the artifacts in reverse order give the same
  six files, byte for byte.

## Ralph Loop

Green: fmt, clippy `-D warnings` (CLI, all targets), tests.
