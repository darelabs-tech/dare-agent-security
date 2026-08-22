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
| `mode` | `discover` or `validate`. |
| `target` | Explicit target — fixture alias, vector id, or stdio executable. |
| `output-dir` | Default `.dare-agent-security` (workspace-relative, no `..`). |
| `fail-on-inconclusive` | Default `true`. |
| `reference-mode` | `validate` only — `secure` (default) or `vulnerable`. |
| `profile` | Optional profile id/path. Empty disables coverage. |
| `coverage-facts` | Typed facts JSON, required when `profile` is set. |
| `min-required-coverage` | Default `0`. |
| `fail-on-required-blocked` | Default `false`. |

## Outputs

| Output | Source |
|---|---|
| `verdict` | `ci-result.json` aggregate. |
| `evidence-path` | Primary evidence file. |
| `summary-path` | `summary.md` under the output directory. |

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
