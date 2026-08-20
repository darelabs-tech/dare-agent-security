# CI result contract (Cycle 004)

Machine-readable aggregate outcome written by the CLI for GitHub Actions and other CI adapters.

## Schema

- **Normative JSON Schema:** `schemas/ci/v1/ci-result.schema.json`
- **Verdict vocabulary:** reuses Cycle 001 `PASS`, `FAIL`, `INCONCLUSIVE`, `ERROR` — no GitHub-specific verdicts.

## Supported Action modes (v0)

| Mode | CLI mapping |
|------|-------------|
| `discover` | `dare-agent-security discover …` |
| `validate` | `dare-agent-security validate coaz-integrity …` |

Modes are enumerated; arbitrary subcommands are rejected by the Action adapter.

## Aggregate precedence

When multiple evidence records are present:

```text
ERROR > FAIL > INCONCLUSIVE > PASS
```

Examples:

- any `ERROR` → aggregate `ERROR`
- else any `FAIL` → aggregate `FAIL`
- else any `INCONCLUSIVE` → aggregate `INCONCLUSIVE`
- else all applicable evidence `PASS` → aggregate `PASS`

`INCONCLUSIVE` is never silently mapped to `PASS`.

## No evidence / partial evidence

| Situation | Aggregate | Notes |
|-----------|-----------|-------|
| Zero evidence files in output directory | `INCONCLUSIVE` | Explicit insufficient-evidence outcome |
| One or more malformed evidence files | `ERROR` | Structural/semantic load failure |
| Mixed valid verdicts | Precedence table above | Counts recorded in `evidence_counts` |

## Process exit semantics

Aligned with existing CLI exit codes (`crates/dare-agent-security-cli/EXIT.md`):

| Aggregate | Exit code | CI step success |
|-----------|-----------|-----------------|
| `PASS` | 0 | yes |
| `FAIL` | 2 | no |
| `ERROR` | 1 | no |
| `INCONCLUSIVE` | 2 if `fail-on-inconclusive: true` (default) | no |
| `INCONCLUSIVE` | 0 if `fail-on-inconclusive: false` | yes |

Default `fail-on-inconclusive` is **true** (conservative).

## Output directory

- Default: `.dare-agent-security` under `GITHUB_WORKSPACE`
- Must resolve inside the workspace; path traversal outside workspace is rejected (task-005/009)
- CI result file: `{output_dir}/ci-result.json`
- Job summary file: `{output_dir}/summary.md`

## GitHub outputs

Written to `GITHUB_OUTPUT` by the Action entrypoint (task-006):

| Output | Source field |
|--------|--------------|
| `verdict` | `aggregate_verdict` |
| `evidence-path` | primary evidence path, or `{output_dir}/evidence/.none` when no records exist |
| `summary-path` | `{output_dir}/summary.md` |

Only non-secret values are written.

## Backwards compatibility

Existing `discover` and `validate coaz-integrity` commands retain their current exit codes when invoked directly. The CI result contract is additive; task-004 wires `--output-dir` and `ci-result.json` emission without breaking direct CLI usage.
