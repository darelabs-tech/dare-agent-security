# task-044 — Security, dependency and container audit

**Status:** DONE  
**Complexity:** MED

## 1. Dependencies

- `cargo audit` (cargo-audit 0.22.2, 1 273 advisories, 321 crates): **exit 0**, no
  advisory.
- `git diff 32909ea -- Cargo.lock` adds exactly one package, `dare-attack-path`. Its
  dependencies are workspace crates and packages that were already locked (`jsonschema`,
  `serde`, `serde_json`, `sha2`, `thiserror`; `tempfile` for tests). No third-party
  dependency was added in this cycle.

## 2. Credential sweep (`scripts/k23/assert_no_real_credentials.py`)

The script is derived from `scripts/k22/`, with the same rules and the same test-module
skipping. It sweeps:
- shipping code: `dare-attack-path/src`, `dare-attack-graph/src/v2` and `path.rs`, the
  CLI's `attack_paths.rs`, the product's `assess.rs`;
- the Cycle 023 tests;
- JSON artifacts: the v2 and system-model schemas, the engine bundles, the 26 lab
  scenarios, the product's v2 fixture, and everything under `.dare-agent-security/`.

Result: **clean** (38 shipping files, 17 test files, 139 artifacts). The refusal corpus's
canary `sk-live-CANARY-VALUE-1234` is shorter than any issued credential, so the shape
patterns do not match it (see the docstring). `attack-path-2026` runs the script.

## 3. Container

- A builder-stage `docker build` of the repository `Dockerfile` (Rust 1.88, the only
  local addition being the proxy CA as a build context) compiled the whole workspace
  with `dare-attack-path`: **exit 0**. Image `dare-agent-security:cycle023-builder`.
- In the image, with `docker run --network none` and the bundle mounted read-only:

  | Input | Result |
  |---|---|
  | the identity bundle with `inputs/scenario.json` edited | `refused: artifact 0: scenario does not match the digest its result pins`, **exit 3**, `/tmp/out` not created |
  | the same bundle unedited (control) | exit 2 (one `CONTROL_UNDECIDED` path), six files written |

## 4. Compatibility

Task-043's `attack_path_compatibility.rs` passes. The frozen boundaries are proven there
and summarised in REGRESSION "Frozen boundaries".

## Ralph Loop

Green: the credential sweep, `cargo audit`, the container build and in-image refusal,
and `ci_job` (the job still matches its test after the new step).
