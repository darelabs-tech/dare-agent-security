# Generated Artifacts

## Product run layout

```text
.dare-security/runs/<run-id>/
  summary.json
  findings.json
  coverage.json
  attack-graph.json
  validation.json
  drift.json
  evidence/
  reports/executive.html
  reports/technical.html
```

| Artifact | Schema / notes |
|---|---|
| `summary.json` | [`schemas/product/v1/summary.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/product/v1/summary.schema.json) |
| `findings.json` | [`schemas/product/v1/findings.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/product/v1/findings.schema.json) |
| `coverage.json` | [`schemas/product/v1/coverage.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/product/v1/coverage.schema.json) — embeds a Cycle 006 coverage report or a placeholder note. |
| `attack-graph.json` | See [Attack Graph](../concepts/attack-graph.md). |
| `evidence/` | [`schemas/evidence/v1/evidence.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/evidence/v1/evidence.schema.json) records — see [Evidence](../concepts/evidence.md). |
| `reports/*.html` | See [Executive](../reports/executive.md) and [Technical](../reports/technical.md) reports. |

## Power-user command artifacts

Each `validate` subcommand writes to its own `--output-dir`, independent of
the product run layout above:

| Command | Artifacts |
|---|---|
| `validate coverage` | `coverage-report.json` |
| `validate benchmark` | `benchmark-run.json`, `aggregate.json`, `records/*.json` |
| `validate attack-graph` | `attack-graph.json`, `paths.json`, `graph.mmd`, `graph.dot`, `summary.md` |
| `validate adversarial` | `validation-result.json`, `evidence.json` |
| `validate continuous` | `security-changeset.json`, `revalidation-plan.json`, `continuous-report.json` |
| `validate identity-security` | `identity-security-result.json`, `identity-security-trials.json`, `identity-security-evidence.json`, `summary.md` |
| `ci write-result` | `ci-result.json` — schema is closed (Cycle 004); product artifacts above are always siblings, never additions to it. |

## Release artifacts

Each GitHub Release publishes, per supported platform: the archive
(`.tar.gz`/`.zip`), plus one shared `SHA256SUMS` file and a CycloneDX SBOM
(`*.cdx.json`) covering the whole workspace — see
[Installation](../getting-started/installation.md).
