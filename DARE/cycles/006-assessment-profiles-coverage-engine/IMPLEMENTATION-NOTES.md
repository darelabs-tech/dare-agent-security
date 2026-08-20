# Cycle 006 — Implementation Notes (task-001 reconciliation)

> Generated: 2026-08-20
> Branch: `agent/cycle-006-assessment-profiles-coverage-engine`
> Baseline merge: `73d6d13` (Cycle 005 merged via PR #10)

Confirms Cycles 001–004 contracts on `main` and records that Cycle 005 **is present**. Core coverage must not treat the lab crate as a second engine.

## Planning zip vs repository reality

| Planning assumption | Actual `main` |
|---------------------|---------------|
| Cycles 001–004 only | Cycles 001–005 (PR #10, commit `73d6d13`) |
| task-013 NOT_APPLICABLE if 005 absent | task-013 **APPLICABLE** |
| Do not import unmerged 005 files | Lab files are **on main**; reuse via isolated adapter only |

This delta is frozen in `APPROVAL.md`. Do not stop execution. Do not copy `dare-mcp-lab` types into the coverage domain model.

## Cycle 001 — Evidence kernel

| Contract | Path |
|----------|------|
| Crate | `crates/dare-security-evidence/` |
| Schema | `schemas/evidence/v1/evidence.schema.json` |
| Verdict | `PASS`, `FAIL`, `INCONCLUSIVE`, `ERROR` (`Verdict` in `verdict.rs`) |

CoverageStatus is a **separate** type in Cycle 006. Do not extend `Verdict`.

## Cycle 002 — Passive MCP discovery

| Contract | Path |
|----------|------|
| Crate | `crates/dare-mcp-discovery/` |
| Inventory schema | `schemas/discovery/v1/inventory.schema.json` |
| Lab vehicle | `labs/synthetic-mcp/` |
| CLI | `dare-agent-security discover` |

Facts for applicability should be derived from inventory-shaped fields (tool/resource/prompt counts, transport, auth presence) without re-implementing discovery.

## Cycle 003 — Authorization-to-execution integrity

| Contract | Path |
|----------|------|
| Crate | `crates/dare-coaz-integrity/` |
| Vectors | `vectors/coaz-mcp/authorization-integrity/v1/` |
| CLI | `dare-agent-security validate coaz-integrity` |
| Evidence bridge | `dare.coaz.integrity` via Cycle 001 records |

Property IDs for tool name / arguments / trusted context map to COAZ-INTEGRITY-004/005/006 class capabilities already on main.

## Cycle 004 — CI security gate

| Contract | Path |
|----------|------|
| Action | `action.yml` (`runs.using: docker`, `image: Dockerfile` at repo root) |
| Entrypoint | `action/entrypoint.sh` |
| CI result schema | `schemas/ci/v1/ci-result.schema.json` (`additionalProperties: false`) |
| CLI CI helper | `dare-agent-security ci write-result` |
| Docs | `docs/ci-gate.md`, `docs/ci-result-contract.md` |
| E2E | `.github/workflows/action-e2e.yml` (`uses: ./`) |

Action inputs on main: `mode`, `target`, `output-dir`, `fail-on-inconclusive`, `reference-mode`.

Cycle 006 must **extend** this contract with optional inputs (`profile`, `min-required-coverage`, `fail-on-required-blocked`) without adding required fields to `ci-result.json` (schema is closed). Emit a sibling `coverage-report.json` and append coverage to `summary.md`.

## Cycle 005 — present on main (adapter only)

| Contract | Path |
|----------|------|
| Crate | `crates/dare-mcp-lab/` |
| Schema | `schemas/lab/v1/scenario.schema.json` |
| Corpus | `labs/scenarios/MCP-LAB-001` … `010` |
| Lab property ids | e.g. `PASSIVE_DISCOVERY_BOUNDARY` (not Cycle 006 registry ids) |

**Do not** use `dare_mcp_lab::CoverageStatus` as the Cycle 006 domain type. Map scenario id → registry property id in `integrations/cycle-005/` only.

## Workspace

```text
crates/dare-security-evidence/
crates/dare-mcp-discovery/
crates/dare-coaz-integrity/
crates/dare-agent-security-cli/   # bin: dare-agent-security
crates/dare-mcp-lab/              # Cycle 005 — adapter consumer only
labs/synthetic-mcp/
```

MSRV: **1.88**. rmcp: **3.1.3**.

CLI package: `dare-agent-security`. Exit codes: `crates/dare-agent-security-cli/EXIT.md`.

## CLI surface (do not add a top-level `coverage` command)

Prefer extending `validate`:

```text
dare-agent-security validate coverage --profile <id-or-path> --facts <path>
```

Optional: `--output-dir`, `--evidence-dir`, `--min-required-coverage`, `--fail-on-required-blocked`.

Existing `discover` / `validate coaz-integrity` / `ci write-result` remain the security engines.

## Property IDs reconciled from 001–004 capabilities

| Registry ID | Source capability |
|-------------|-------------------|
| `MCP.DISCOVERY.PASSIVE_BOUNDARY` | Cycle 002 passive list-only |
| `MCP.DISCOVERY.EXPLICIT_TARGET` | Cycle 002 explicit target |
| `MCP.AUTHZ.PER_OPERATION` | Cycle 002 authorization presence |
| `MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME` | Cycle 003 tool-name binding |
| `MCP.AUTHZ.EXECUTION_INTEGRITY.ARGUMENTS` | Cycle 003 arguments binding |
| `MCP.AUTHZ.EXECUTION_INTEGRITY.CONTEXT` | Cycle 003 trusted context |
| `MCP.EVIDENCE.REDACTION` | Cycle 001 redaction kernel |
| `MCP.IDENTITY.CONFUSED_DEPUTY` | Capability flag; lab mapping via adapter |

Lab-only IDs (`MCP_ROUTING_*`, `MRTR_*`, issuer binding) stay **out of the core registry** and are recorded as unmapped/future in the adapter.

## Paths for tasks 002–014

| Task | Intended location |
|------|-------------------|
| 002 | `schemas/coverage/v1/property.schema.json`, `schemas/coverage/v1/registry.json`, `crates/dare-coverage/` |
| 003 | `schemas/coverage/v1/profile.schema.json`, `profiles/mcp-security-baseline.json` |
| 004 | `crates/dare-coverage/src/status.rs` |
| 005 | `crates/dare-coverage/src/math.rs` |
| 006 | `crates/dare-coverage/src/applicability.rs`, `facts.rs` |
| 007 | `crates/dare-coverage/src/plan.rs` |
| 008 | `crates/dare-coverage/src/correlate.rs` |
| 009 | `fixtures/coverage/` |
| 010 | `crates/dare-coverage/src/report.rs`, `schemas/coverage/v1/coverage-report.schema.json` |
| 011 | CLI `validate coverage`, Action optional inputs, `summary.md` appendix |
| 012 | `crates/dare-coverage/tests/adversarial.rs` |
| 013 | `integrations/cycle-005/` + `crates/dare-coverage` feature `cycle005` |
| 014 | `docs/assessment-coverage.md`, `PROOF.md` |

## Invariants for later tasks

- Profiles are data (JSON), never executable code.
- Applicability uses a closed predicate enum — no expression language, no LLM.
- CoverageStatus ≠ Verdict.
- Denominator excludes `NOT_APPLICABLE` and `OUT_OF_SCOPE`.
- ROE `BLOCKED` must never be relabeled `NOT_APPLICABLE`.
- `ci-result.schema.json` stays closed; coverage is a sibling artifact.
