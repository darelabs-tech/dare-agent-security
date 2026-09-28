# task-001 — Record the post-022 baseline, v1 golden digests and observations O-1..O-4

**Status:** DONE  
**Complexity:** LOW

## Commands and results

- `git rev-parse 32909ea^{tree} c2f56b3^{tree}`: both give `9d440e666f4325efddb838ad19ec7b0aa7768f45`.
- `cargo test --workspace --no-fail-fast` on `c2f56b3` (same tree): 314 suites, 4 224 passed,
  0 failed, 4 ignored.
- `validate attack-graph --facts` was run for each of the 5 `fixtures/attack-graph/*.json` with
  the binary built at `32909ea`. Every run exited 0. `sha256sum` was taken of
  `attack-graph.json` and `paths.json`, and a second run gave identical digests. The values
  are in `BASELINE.md`.
- Member, registry, profile and CI-job counts, plus the registry digests, were measured over
  the repository files. The values are in `BASELINE.md`.
- Observations O-1..O-4 were located by `grep` and are recorded with file:line.

## Action image

PR #47 (the same tree) merged with every check green, including `Action E2E`. The
criterion allows citing that run.

## Ralph Loop

- Build/Test: green (above).
- Lint/Audit: no code change.
