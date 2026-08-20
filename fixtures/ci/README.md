# CI Action fixtures (Cycle 004)

Synthetic-only matrix for GitHub Action E2E. No network access to customer or production services.

## Matrix

See [`matrix.json`](matrix.json) for the canonical case list.

| Case | Mode | Target | Expected |
|------|------|--------|----------|
| secure-pass | validate | `secure-pass` | PASS / exit 0 |
| fail-stale-permit | validate | `fail-stale-permit` | FAIL / exit 2 |
| inconclusive-empty | validate | `inconclusive-empty` | INCONCLUSIVE / exit 2 |
| discover-synthetic-mcp | discover | `synthetic-mcp` | PASS / exit 0 |

## Reuse

- **Cycle 003:** built-in `COAZ-INTEGRITY-*` vectors via `validate coaz-integrity`
- **Cycle 002:** `labs/synthetic-mcp` via `discover --stdio`
- **Cycle 001:** evidence schema unchanged; files under `{output_dir}/evidence/`

Target aliases are resolved in `action/entrypoint.sh` — the Action adapter contains no domain logic.

## ERROR case

Use target `error-invalid-fixture` in manual hostile tests (task-009). Not in default E2E matrix because the step must fail before output assertions.
