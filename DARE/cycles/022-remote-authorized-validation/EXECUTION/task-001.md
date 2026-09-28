# task-001 — Freeze post-021 baseline, test count, pinned denominators and Action image build

**Status:** DONE  
**Complexity:** LOW

## Commands and results

- `git rev-parse 4d691d1^{tree} b6f14b9^{tree}`: both give `6011b9655fdb9a8dd588f8dfdbd6110b4baf07b0`
- `cargo test --workspace`: 280 suites, 3 955 passed, 0 failed, 3 ignored
- The registry, profile, member and CI-job counts were measured with a script over the repository files (values in `BASELINE.md`)
- `no_earlier_profile_denominator_moved` passes (inside the workspace run)

## Action image

The builder stage was built on this exact tree in this session (Cycle 021 task-035),
which the criterion allows. The runtime-stage limit is recorded in `BASELINE.md`.

## Ralph Loop

- Build/Test: green (above)
- Lint/Audit: no code change
