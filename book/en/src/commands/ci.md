# `ci`

CI adapter helpers for GitHub Actions. No domain security logic lives here —
this is a thin adapter over evidence already produced by `discover` /
`validate`.

## `ci write-result`

Write an aggregate `ci-result.json` from the current evidence directory (or
an empty/`INCONCLUSIVE` result if none exists).

```bash
dare-agent-security ci write-result \
  --mode validate \
  --output-dir .dare-agent-security/pr \
  --fail-on-inconclusive true \
  --target-label secure-pass
```

| Option | Description |
|---|---|
| `--mode` | `discover` or `validate`. |
| `--output-dir` | Path containing the evidence to aggregate. |
| `--fail-on-inconclusive` | Default `true`. |
| `--target-label` | Safe label included in the job summary — never raw credentials or payloads. |

This is what powers the repository-local `action.yml` GitHub Action — see
[GitHub Actions](../ci/github-actions.md) for the composite-action usage,
which is the recommended way to consume this in a real workflow rather than
calling `ci write-result` directly.
