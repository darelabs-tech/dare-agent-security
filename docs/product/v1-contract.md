# DARE Agent Security — Product v1 public contract

Stable for v1.0 release readiness (Cycle 011).

## Primary CLI

```text
dare-agent-security init [PATH] [--force] [--name NAME] [--confidential]
dare-agent-security assess <PATH> [--confidential] [--offline] [--config PATH] [--run ID] [--json]
dare-agent-security report [--path PATH] [--run ID] [--refresh] [--json]
dare-agent-security doctor [PATH] [--json]
```

Power-user commands remain: `discover`, `validate *`, `ci`.

Binary name: `dare-agent-security` (alias documentation may refer to `dare-security`).

## Config v1

Schema: [`schemas/product/v1/config.schema.json`](../../schemas/product/v1/config.schema.json)

Search order under the target root:

1. `dare-security.yaml` / `.yml` / `.json`
2. `.dare-security/config.yaml` / `.yml` / `.json`

Defaults: telemetry off, network restricted, profile `mcp-security-baseline`, formats html+json.

## Artifact layout

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

Cycle 004 `ci-result.json` schema stays closed — product artifacts are siblings only.

## Report JSON

- Summary: `schemas/product/v1/summary.schema.json`
- Findings: `schemas/product/v1/findings.schema.json`

## Exit codes

See [`crates/dare-agent-security-cli/EXIT.md`](../../crates/dare-agent-security-cli/EXIT.md).

## Privacy

`--confidential` / `--offline` (and config equivalents) are fail-closed: no telemetry, prohibited egress denied. Safe defaults remain static/passive/plan-only.

## Non-public

Internal crate layout and Cycles 001–010 module structure are not part of the public contract.
