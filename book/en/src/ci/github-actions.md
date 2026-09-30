# GitHub Actions

The repository ships a repository-local GitHub Action (`action.yml`) that
wraps the CLI with a deterministic aggregate verdict for CI.

> **Status:** pre-release. Not published to the GitHub Marketplace, no
> stable `v1` tag promise yet. Pin to an immutable commit SHA for
> high-assurance use, not a moving branch ref.

## What it is

```text
GitHub workflow → action.yml (Docker) → entrypoint.sh → dare-agent-security → evidence + ci-result.json
```

A thin adapter — it does not duplicate any discovery, integrity-validation,
or evidence logic. It always writes a `ci-result.json` (schema: closed,
Cycle 004) and a `summary.md`.

## Inputs

| Input | Description |
|---|---|
| `mode` | `discover`, `validate`, `runtime-telemetry`, `attack-paths` or `blast-radius`. |
| `target` | `discover`/`validate` only — fixture alias, vector id, or stdio executable. |
| `output-dir` | Default `.dare-agent-security` (workspace-relative, no `..`). |
| `fail-on-inconclusive` | Default `true`. |
| `reference-mode` | `validate` only — `secure` (default) or `vulnerable`. |
| `profile` | Optional profile id/path. Empty disables coverage. |
| `coverage-facts` | Typed facts JSON, required when `profile` is set. |
| `min-required-coverage` | Default `0`. |
| `fail-on-required-blocked` | Default `false`. |
| `traces` | `runtime-telemetry` only — OTLP/JSON trace exports, whitespace-separated (1 to 64). |
| `policy` | `runtime-telemetry` only — runtime policy JSON (optional). |
| `artifacts` | `attack-paths` only — engine artifact directories, whitespace-separated (1 to 64). |
| `system-model` | `attack-paths` only — system model JSON (optional). |
| `graph` | `blast-radius` only — `attack-graph.json` from an `attack-paths` run. |
| `compromise` | `blast-radius` only — compromise scenario JSON; empty seeds every entry point. |

## Outputs

| Output | Source |
|---|---|
| `verdict` | `ci-result.json` aggregate, or the engine result in the engine modes. |
| `evidence-path` | Primary evidence file. |
| `summary-path` | `summary.md` under the output directory. |

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

## What it does not do

- Active adversarial mutation against production targets.
- Host enumeration or scope expansion.
- Marketplace distribution or stable release claims.
- SARIF / Check Runs / PR comments.
- LLM-as-judge verdicts.

## Reference

Full detail: [`docs/ci-gate.md`](https://github.com/darelabs-tech/dare-agent-security/blob/main/docs/ci-gate.md),
[`docs/ci-result-contract.md`](https://github.com/darelabs-tech/dare-agent-security/blob/main/docs/ci-result-contract.md),
[`action/ARCHITECTURE.md`](https://github.com/darelabs-tech/dare-agent-security/blob/main/action/ARCHITECTURE.md),
[`action/THREAT-MODEL.md`](https://github.com/darelabs-tech/dare-agent-security/blob/main/action/THREAT-MODEL.md).
