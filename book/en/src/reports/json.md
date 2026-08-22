# JSON Artifacts

Every HTML report is rendered from machine-readable JSON — use these
directly for scripting, dashboards, or CI gates instead of scraping HTML.

## Product report schemas

| File | Schema |
|---|---|
| `summary.json` | [`schemas/product/v1/summary.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/product/v1/summary.schema.json) |
| `findings.json` | [`schemas/product/v1/findings.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/product/v1/findings.schema.json) |
| `coverage.json` | [`schemas/product/v1/coverage.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/product/v1/coverage.schema.json) |

## Getting a summary on stdout

```bash
dare-agent-security assess . --offline --json
dare-agent-security report --json
```

`assess --json` emits the summary JSON directly; `report --json` prints
artifact paths only (it does not re-emit report content).

## Stability

`.dare-security/` artifact layout and these schemas are part of the
documented v1 public contract — see
[`docs/product/v1-contract.md`](https://github.com/darelabs-tech/dare-agent-security/blob/main/docs/product/v1-contract.md).
The Cycle 004 `ci-result.json` schema is a separate, closed contract — see
[GitHub Actions](../ci/github-actions.md); product artifacts are siblings
only, never additions to that schema.
