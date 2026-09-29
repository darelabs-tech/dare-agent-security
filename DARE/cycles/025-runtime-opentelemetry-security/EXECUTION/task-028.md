# task-028 — Add the `runtime-telemetry-2026` CI job and the k25 scripts

**Status:** DONE. The CI trigger change approved for this task is **stopped for Review**
(R-9).  
**Complexity:** LOW

## CI job `runtime-telemetry-2026` (`.github/workflows/ci.yml`)

The job is placed before `docs-build` and runs these steps:
1. the crate's lib, manifest, result, evidence and summary tests;
2. OTEL-LAB;
3. no-value-leaves, determinism and hostile;
4. the release **scale** test;
5. `ci_job`;
6. the CLI `runtime_telemetry_cli` and `runtime_telemetry_refusals`;
7. coverage: `runtime_telemetry_properties`, `runtime_telemetry_profile` and the
   adapted `multi_turn_properties` (R-7);
8. the BQ-1 pins: `dare-remote-validation --test compatibility` and
   `attack_path_compatibility`;
9. the Cycle 023 projector (`projection_tables`, `binding`), the 156 goldens and
   ATTACK-PATH-LAB, and the Cycle 024 BRL lab;
10. the k25 credential sweep and proof-citation check;
11. an offline CLI run: recorded OTL-001 exits 2 and writes four files; a doctored
    OTL-055 exits 3 and writes nothing. This was verified locally.

It uses only `actions/checkout@v4` and `dtolnay/rust-toolchain@stable`.

**`crates/dare-runtime-telemetry/tests/ci_job.rs` (3 tests)** asserts:
- the trigger, and that the 022–024 gates are kept;
- that every step above is present;
- that the job references no `secrets.`, no URL, no `curl`/`wget`, no `OTEL_`
  variable, no port 4317/4318, no `--endpoint`/`--collector`, no `otelcol` and no
  `services:` container. This is RS-08: CI never starts a collector.

The Cycle 023 and 024 `ci_job` tests and the 021/022 trigger tests still pass. The
workflow parses as YAML.

## k25 scripts

- **`scripts/k25/assert_no_real_credentials.py`** is derived from k24.
  - It sweeps 29 shipping files (the runtime crate, the CLI module and the projector),
    14 test files, and 124 artifacts (schemas, the pinned mapping and provenance, the
    profile, the recorded OTEL-LAB copies and the `rt` bundle).
  - **Addition:** a value carrying the product's synthetic marker
    `DARE-SYNTHETIC-CANARY-` is removed before the shape patterns run. Every planted
    credential-shaped test value in this cycle now carries it. Three test values were
    changed to it: `evidence.rs`, `summary.rs`, and `hostile.rs`, where the
    `BEGIN PRIVATE KEY` value became `-----BEGIN DARE-SYNTHETIC-CANARY-…`.
  - **Also added:** telemetry-collector endpoints (`:4317`, `:4318`, `otel-collector`,
    vendor intakes) as forbidden in shipping code.
  - **Allowed:** exactly the two quoted upstream repository URLs of the pinned
    semantic conventions in the provenance record.
  - **Result:** clean. A probe showed that a real-length `Bearer …` in a test fails
    and a synthetic one passes.
- **`scripts/k25/verify_proof_citations.py`** is derived from k24 with the Cycle 025
  roots and API names. It runs in task-031, once `PROOF.md` exists.

## CI trigger (approved in Review; not applied, R-9)

Adding `synchronize` breaks two **frozen engine** tests (Cycles 021 and 022) that pin
"`pull_request` opened only", and the 023/024 `ci_job` tests. Fixing the engine tests
means editing engine trees 021/022 and re-pinning their digests, which goes beyond
BQ-1, so the task stops on this point.

Options for the Product Owner:
- **(a)** Extend the exception so the four trigger assertions (021, 022, 023, 024) accept
  `[opened, synchronize, reopened]` plus `workflow_dispatch`, and re-pin the two engine
  tree digests.
- **(b)** Add only `workflow_dispatch`. It keeps `types: [opened]`, and every trigger
  test passes as written, but it adds a manual trigger those tests did not foresee.
- **(c)** Leave the trigger as it is and re-run CI by reopening the PR.

## Ralph Loop

| Step | Result |
|---|---|
| Build | ok |
| Test | `ci_job` 3/3 (025), 3/3 (024), 3/3 (023); 021/022 compatibility 5/5 and 8/8; CLI reconcile and discover suites that read `ci.yml` pass; evidence, hostile and summary pass after the synthetic-marker change |
| Lint | fmt; YAML parses |
| Audit | No dependency change; k25 sweep clean |
