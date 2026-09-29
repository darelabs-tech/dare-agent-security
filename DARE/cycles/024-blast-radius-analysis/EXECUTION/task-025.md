# task-025 — Add the `blast-radius-2026` CI job

**Status:** DONE  
**Complexity:** LOW

`.github/workflows/ci.yml` gains the job `blast-radius-2026` after `attack-path-2026`.
It keeps the workflow's `pull_request: types: [opened]` trigger, uses only
`actions/checkout@v4` and `dtolnay/rust-toolchain@stable`, and references no secret and
no network target.

## Steps

1. The Cycle 023 goldens: 156 digests over the frozen runs.
2. The shared continuity and sweep rules (`dare-attack-graph --lib v2`).
3. The crate tests: `lib`, manifest, scenario, reach, classify (the 0-false-CONTAINED
   property test), impact and delta, validate, analyze and views.
4. The **release** scale test.
5. `ci_job`.
6. The CLI and the refusal corpus.
7. BLAST-RADIUS-LAB.
8. The Cycle 023 lab, CLI and compatibility tests, unchanged.
9. The two `scripts/k24/` gates.
10. Two offline CLI checks:
    - an identity bundle graph with `--seed-entry-points` gives exit 2, four files and
      `totals.exposed=1` (checked with `scripts/assert-json.py`);
    - a graph edited after sealing gives exit 3, and the output directory is never
      created.

Both offline steps were run locally against the built binary, and both passed: 4
assertions held, and the refusal behaved as expected.

## Test (`crates/dare-blast-radius/tests/ci_job.rs`)

Derived from `dare-attack-path/tests/ci_job.rs`. It checks three things:
- the trigger is still `opened`, and the earlier gates, including `attack-path-2026`,
  are still present;
- the job contains the lab, CLI, release scale, classify, goldens and credential-sweep
  steps;
- the job has no `secrets.`, no URL, no `curl` or `wget`, and no live mode, and every
  `uses:` is one of the two pinned actions.
