# `report`

Show or refresh reports for an assessment run.

## Syntax

```bash
dare-agent-security report [--path PATH] [--run ID] [--refresh] [--json]
```

## Options

| Option | Description |
|---|---|
| `--path PATH` | Project root containing `.dare-security/runs`. Default: current directory. |
| `--run ID` | Specific run id. Default: the latest run. |
| `--refresh` | Re-render HTML reports from the stored JSON, without re-running the assessment. |
| `--json` | Print artifact paths only (no HTML rendering). |

## Examples

```bash
dare-agent-security report
dare-agent-security report --path examples/vulnerable-mcp
dare-agent-security report --run my-run-001 --refresh
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Report generated/refreshed successfully. |
| 1 | Environment or internal error. |
| 2 | — (not applicable to `report`) |
| 3 | Configuration error (e.g. no run found at the given path/id). |

## Generated artifacts

`reports/executive.html` and `reports/technical.html` under the run
directory, sourced from `summary.json` and `findings.json` — see
[Executive Report](../reports/executive.md) and
[Technical Report](../reports/technical.md).
