# task-001 — Freeze post-020 baseline, test count, pinned denominators and Action image build

**Status:** DONE  
**Cycle:** 021 — Adaptive Multi-Turn Adversarial Execution  
**Complexity:** LOW

## Objective

Measure the repository state Cycle 021 starts from, so that every later claim is a
difference against an observed number.

## Files changed

- `DARE/cycles/021-adaptive-multi-turn-adversarial-execution/BASELINE.md` (new)
- `DARE/cycles/021-adaptive-multi-turn-adversarial-execution/EXECUTION/task-001.md` (this record)
- `DARE/cycles/021-adaptive-multi-turn-adversarial-execution/TASKS.md` (checkbox)

## Commands executed

```
git merge-base --is-ancestor 4ca06b2 HEAD            # ok
cargo test --workspace | grep '^test result:'        # 264 suites, 3767 passed, 0 failed, 3 ignored
python3 <registry/profile/CI/member counts>          # 58 / 10 / 18 / 20
dockerd & ; docker build -t dare-agent-security:baseline .   # failed: Docker Hub 429
docker pull debian:bookworm-slim; docker pull rust:1.88-bookworm   # failed: 429 (retry)
GitHub API: action-e2e.yml runs                      # run 36339198428 success on 9977c5c
git diff --stat 9977c5c 4ca06b2                      # Cargo.lock only
```

## Result

Every value in the DONE criterion is recorded in `BASELINE.md`. The Action image
criterion is met through the fallback that the criterion allows (the last green
`action-e2e` run), because Docker Hub rate-limited the local build. The gap is recorded
honestly: the image has not yet been built with the lockfile bump. That check carries
over to task-035.

## Ralph Loop

- Build/Test: `cargo test --workspace` green (3 767 passed, 0 failed)
- Lint: n/a (no code changed)
- Audit: n/a (no dependency changed)

## Security

- No code, dependency, credential or network capability added.
