# `assess`

Run a unified product assessment. Orchestrates discovery, coverage,
attack-graph, and validation engines and produces a single gate verdict plus
reports.

## Syntax

```bash
dare-agent-security assess <PATH> [--confidential] [--offline] [--config PATH] [--run ID] [--json]
```

## Arguments

| Argument | Description |
|---|---|
| `PATH` | Path to the project or demo fixture root to assess. |

## Options

| Option | Description |
|---|---|
| `--confidential` | Enable confidential classification and fail-closed privacy. |
| `--offline` | Deny all network/telemetry egress (fail-closed). |
| `--config PATH` | Explicit product config path, overriding the default search order. |
| `--run ID` | Stable run id (safe path segment) instead of an auto-generated one. |
| `--json` | Emit the summary JSON to stdout. |

## Examples

```bash
dare-agent-security assess examples/vulnerable-mcp --offline --confidential
dare-agent-security assess . --offline --run my-run-001
dare-agent-security assess . --json
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Gate `PASS`. |
| 1 | Environment or internal error. |
| 2 | Gate `FAIL` \| `PARTIAL` \| `BLOCKED` \| `INCONCLUSIVE`. |
| 3 | Configuration or unsupported target / usage error. |

A non-zero exit on a real target is a normal, expected outcome — it means
the assessment ran and found something, or was correctly blocked.

## Generated artifacts

A full run directory under `.dare-security/runs/<run-id>/` — see
[Generated Artifacts](../reference/artifacts.md) for the complete layout.

## Security implications

Known v1 limitation: product `assess` orchestrates the existing engines via
offline fixtures for demos; live MCP discovery against a real target remains
the power-user `discover` command (see [`docs/product/packaging-install.md`](https://github.com/darelabs-tech/dare-agent-security/blob/main/docs/product/packaging-install.md)
for the current known-limitations list). `--offline`/`--confidential` are
fail-closed — see [Privacy](../privacy/confidential-mode.md).
