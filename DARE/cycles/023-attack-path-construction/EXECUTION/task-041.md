# task-041 — Add the `attack-path-2026` CI job

**Status:** DONE  
**Complexity:** LOW

## Change

`.github/workflows/ci.yml` gains the job `attack-path-2026`. It sits after
`remote-validation-2026`, and the workflow trigger (`pull_request`, `types: [opened]`)
is unchanged. Its steps:

| Step | Command |
|---|---|
| v1 output byte-identical | `cargo test -p dare-attack-graph --test v1_unchanged` |
| v2 contract | `--lib v2`, `--test v2_contract` |
| Containment, limits, ids, model | `dare-attack-path` `--lib`, `manifest`, `error_messages`, `model` |
| Binding, projectors, merge, paths | `binding`, `generate_static_inputs`, `projection_tables`, `graph`, `paths` |
| Scale (release) | `cargo test -p dare-attack-path --release --test scale` |
| Job shape | `cargo test -p dare-attack-path --test ci_job` |
| Refusal corpus | `cargo test -p dare-agent-security --test attack_paths_cli` |
| ATTACK-PATH-LAB | `cargo test -p dare-agent-security --test attack_path_lab` |
| Offline CLI | two committed bundles → exit 2, six files, `assert-json.py` on the graph and paths; the same run twice → exit 3, nothing written |

The credential sweep and PROOF-citation steps (`scripts/k23/…`) are added with
task-044 and task-046, which create those scripts.

## Test (`crates/dare-attack-path/tests/ci_job.rs`)

- The first 8 lines keep `pull_request:` and `types: [opened]`, and the earlier gates are
  kept.
- The job runs the lab, the refusal corpus, the release scale test and the v1 goldens.
- The job text contains none of `secrets.`, `http://`, `https://`, `curl `, `wget `,
  `--mode live` or `validate remote `. It uses only `actions/checkout@v4` and
  `dtolnay/rust-toolchain@stable`.

## Ralph Loop

- `python scripts/run-ci-job-locally.py .github/workflows/ci.yml attack-path-2026`: all
  10 steps PASS.
- The other tests that read `ci.yml` pass unchanged: remote-validation and multi-turn
  `compatibility`, `cycle004_reconcile`, `cycle005_reconcile`, `discover_cli` and
  `e2e_proof`.
- fmt and clippy `-D warnings` are green. No dependency changed.
