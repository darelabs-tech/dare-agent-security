# GitHub Action CI gate (Cycle 004)

**Status:** Pre-release — repository-local Action (`uses: ./`). Not published to GitHub Marketplace. No stable `v1` tag promise.

## What it does

The Action is a **thin adapter** over the existing `dare-agent-security` CLI:

```text
GitHub workflow → action.yml (Docker) → entrypoint.sh → dare-agent-security → evidence + ci-result.json
```

It does **not** duplicate MCP discovery, COAZ integrity validation, or evidence logic.

## Supported inputs (v0)

| Input | Description |
|-------|-------------|
| `mode` | `discover`, `validate`, `runtime-telemetry`, `attack-paths` or `blast-radius` (bounded enum) |
| `target` | `discover`/`validate` only — fixture alias, vector id, or stdio executable |
| `output-dir` | Default `.dare-agent-security` (workspace-relative, no `..`) |
| `fail-on-inconclusive` | Default `true` — exit non-zero on `INCONCLUSIVE` |
| `reference-mode` | `validate` only — `secure` (default) or `vulnerable` |
| `profile` | Optional Cycle 006 profile id/path. Empty = coverage off |
| `coverage-facts` | Typed facts JSON (required when `profile` is set) |
| `min-required-coverage` | Default `0` — fail if required coverage is below this ratio |
| `fail-on-required-blocked` | Default `false` — fail if a REQUIRED property is BLOCKED |
| `traces` | `runtime-telemetry` only — OTLP/JSON trace exports, whitespace-separated (1 to 64) |
| `policy` | `runtime-telemetry` only — runtime policy JSON (optional) |
| `artifacts` | `attack-paths` only — engine artifact directories, whitespace-separated (1 to 64) |
| `system-model` | `attack-paths` only — system model JSON (optional) |
| `graph` | `blast-radius` only — `attack-graph.json` from an `attack-paths` run |
| `compromise` | `blast-radius` only — compromise scenario JSON; empty seeds every entry point |

Coverage is written to `coverage-report.json` and appended to `summary.md`. It does **not** add fields to `ci-result.json` (that schema is closed).

## Outputs

| Output | Source |
|--------|--------|
| `verdict` | `ci-result.json` aggregate (`discover`/`validate`), or the engine result (engine modes) |
| `evidence-path` | Primary evidence file |
| `summary-path` | `summary.md` under output dir |

Written via `github-output.env` — never includes secrets or raw MCP payloads.

## Engine modes (Cycles 023–025)

Three more `mode` values run an engine directly and restate its result as the
same three outputs, through `dare-agent-security ci engine-outputs`:

| `mode` | Engine | `verdict` is read from | `evidence-path` |
|---|---|---|---|
| `runtime-telemetry` | `validate runtime-telemetry` | `runtime-telemetry-result.json` `verdict` | `runtime-telemetry-evidence.json` |
| `attack-paths` | `validate attack-paths` | FAIL on a feasible `CONTROL_FAILED` path; INCONCLUSIVE on `CONTROL_UNDECIDED` or truncation | `attack-paths.json` |
| `blast-radius` | `validate blast-radius` | FAIL when a target is `EXPOSED`; INCONCLUSIVE on truncation | `blast-radius.json` |

An engine refusal (exit 3) or internal error (exit 1) is `verdict=ERROR` with
`evidence-path` ending in `/.none`, and the step fails with the engine's own
exit code. An exit code that contradicts the result document is ERROR too:
the adapter never guesses. These modes write the engine's own artifacts and
`summary.md`, not `ci-result.json` (that schema is closed to
`discover`/`validate`). File inputs must be workspace-relative, without `..`
and not starting with `-`; list inputs are split on whitespace, with no
globbing, so a path cannot contain a space.

```yaml
- name: Attack paths over the engine runs of this PR
  id: paths
  uses: ./
  continue-on-error: true   # still run blast radius when a path is found
  with:
    mode: attack-paths
    artifacts: |
      .dare/identity
      .dare/rag
    output-dir: .dare-agent-security/paths

- name: What a compromise reaches
  uses: ./
  with:
    mode: blast-radius
    graph: .dare-agent-security/paths/attack-graph.json
    output-dir: .dare-agent-security/blast

- name: Recorded production traces against the runtime policy
  uses: ./
  with:
    mode: runtime-telemetry
    traces: telemetry/export-0.json telemetry/export-1.json
    policy: security/runtime-policy.json
    output-dir: .dare-agent-security/runtime
```

## Minimum permissions

```yaml
permissions:
  contents: read
```

No write token, no GitHub API calls from the Action core.

## Example workflow

```yaml
- uses: actions/checkout@v4

- name: COAZ integrity gate (synthetic)
  uses: ./
  with:
    mode: validate
    target: secure-pass
    output-dir: .dare-agent-security/pr

- name: Upload evidence
  uses: actions/upload-artifact@v4
  with:
    name: dare-security-evidence
    path: .dare-agent-security/pr/
```

Pin high-assurance use to an **immutable commit SHA** instead of a moving branch ref.

## Synthetic fixture aliases

See [`fixtures/ci/README.md`](../fixtures/ci/README.md) for the PASS / FAIL / INCONCLUSIVE matrix.

| Target | Expected |
|--------|----------|
| `secure-pass` | PASS |
| `fail-stale-permit` | FAIL (requires `reference-mode: vulnerable`) |
| `inconclusive-empty` | INCONCLUSIVE |
| `synthetic-mcp` | PASS (`discover` mode) |

## What it does not do

- Active adversarial mutation against production targets
- Host enumeration or scope expansion
- Marketplace distribution or stable release claims
- SARIF / Check Runs / PR comments
- LLM-as-judge verdicts

## Contracts

- CI aggregate: [`docs/ci-result-contract.md`](ci-result-contract.md)
- Evidence schema: [`schemas/evidence/v1/evidence.schema.json`](../schemas/evidence/v1/evidence.schema.json)
- Architecture: [`action/ARCHITECTURE.md`](../action/ARCHITECTURE.md)
- Threat model: [`action/THREAT-MODEL.md`](../action/THREAT-MODEL.md)

## E2E

Repository workflow: [`.github/workflows/action-e2e.yml`](../.github/workflows/action-e2e.yml) invokes `uses: ./` against synthetic fixtures only. Job `action-engines` runs the engine modes on the recorded OTEL-LAB traces (OTL-001 FAIL, OTL-002 PASS, OTL-055 refused → ERROR) and the Cycle 023 artifact bundles (PASS, FAIL, INCONCLUSIVE tolerated), chains `blast-radius` on the graphs written, and checks that a traversal path is rejected before the CLI runs.
