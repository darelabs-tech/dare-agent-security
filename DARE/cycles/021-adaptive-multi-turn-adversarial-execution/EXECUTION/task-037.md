# task-037 — Write REGRESSION.md and PROOF.md and run the completion gate

**Status:** DONE  
**Complexity:** MED

## Files changed

- `DARE/cycles/021-.../REGRESSION.md` (new): 9 defects or design gaps found during execution, 7 recorded deviations, the mutation check and environment findings
- `DARE/cycles/021-.../PROOF.md` (new): objectives O-01…07, RF-01…18, RS-01…10 and compatibility items 1–6, each mapped to executed tests; measured totals
- `scripts/k21/verify_proof_citations.py` (new): Cycle 021 paths, with the same rules as Cycle 020
- `.github/workflows/ci.yml`: the citation gate is added to `multi-turn-security-2026` (13 steps)
- `DARE/.canvas.md`: regenerated
- `TASKS.md`: cycle status set to complete

## Completion gate (all executed)

| Gate | Result |
|---|---|
| `cargo fmt --all --check` | green |
| `cargo clippy --workspace --all-targets -- -D warnings` | green |
| `cargo test --workspace` | 280 suites, 3 955 passed, 0 failed, 3 ignored |
| `cargo audit` | exit 0 |
| CI job, run locally | 13/13 steps passed |
| `mdbook build book/en` and `book/pt` | exit 0 |
| `verify_proof_citations.py` | 82 cited names verified against 445 tests (2 historical names confirmed absent) |
| `assert_no_real_credentials.py` | clean |
| `regen-canvas.py --check` | current |

The Cycle 012–020 regressions are included in `cargo test --workspace`, and all pass.

## Not done here (by design)

- The final branch head was pushed to `claude/loving-newton-113zme`. **No pull request
  was opened, and nothing was merged.** Merge to `main` needs human approval.
- The full two-stage Action image is proven by `action-e2e.yml` on the pull request
  (see task-035 for why the runtime stage cannot run in this session).
