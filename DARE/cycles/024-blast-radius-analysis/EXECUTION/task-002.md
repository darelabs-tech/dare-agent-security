# task-002 — Extract the shared lab runner and pin the ATTACK-PATH-LAB output goldens

**Status:** DONE  
**Complexity:** MED

## Shared runner (`crates/dare-agent-security-cli/tests/common/lab_runner.rs`)

The following move out of `attack_path_lab.rs` unchanged:
- `bin`, `repo`, `read_json`, `copy_dir`, `shipped_scenario`, `run_engine`,
  `result_file`, `substitute`, `Outcome`, `attack_paths` and `walk`;
- `lab_root`/`scenarios`, now named `apl_root`/`apl_scenarios`.

A new `build_apl(dir, tmp) -> Built` holds the O-01 check, the engine runs and the model
rendering that `check()` used to hold. `attack_path_lab.rs` now calls it, and its
assertions are unchanged. `attack_path_lab` passes (26 scenarios, class contract).

## Goldens (`crates/dare-agent-security-cli/tests/attack_path_goldens.rs`)

| Test | Proves |
|---|---|
| `every_attack_path_lab_output_keeps_its_baseline_digest` | For each of the 26 scenarios, `validate attack-paths` runs over the frozen runs with the scenario's rendered system model. It checks `engine.commit == "unrecorded"`, then that each of the six files hashes to its golden (156 checks) |
| `the_frozen_runs_match_the_lab` | The set of frozen run directories equals the set of `(engine, scenario)` runs that the lab's `lab.json` files name: 35 |
| `regenerate_frozen_runs_and_goldens` (ignored) | Baseline-only generator. It was run once on the unchanged tree to write the 35 frozen runs and `attack-path-lab-goldens.txt` |

REGRESSION R-1 explains why the goldens use frozen runs rather than fresh engine runs.

## Ralph Loop

Green: fmt, clippy `-D warnings --tests`, `attack_path_goldens` (2 passed, 1 ignored)
and `attack_path_lab`. The k23 credential sweep is clean. No dependency changed.
