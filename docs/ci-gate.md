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
| `mode` | `discover` or `validate` (bounded enum) |
| `target` | Explicit target — fixture alias, vector id, or stdio executable |
| `output-dir` | Default `.dare-agent-security` (workspace-relative, no `..`) |
| `fail-on-inconclusive` | Default `true` — exit non-zero on `INCONCLUSIVE` |
| `reference-mode` | `validate` only — `secure` (default) or `vulnerable` |

## Outputs

| Output | Source |
|--------|--------|
| `verdict` | `ci-result.json` aggregate |
| `evidence-path` | Primary evidence file |
| `summary-path` | `summary.md` under output dir |

Written via `github-output.env` — never includes secrets or raw MCP payloads.

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

Repository workflow: [`.github/workflows/action-e2e.yml`](../.github/workflows/action-e2e.yml) invokes `uses: ./` against synthetic fixtures only.
