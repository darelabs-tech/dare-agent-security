# Cycle 004 — Implementation Notes (task-001 reconciliation)

> Generated: 2026-08-20
> Branch: `agent/cycle-004-ci-security-gate`
> Baseline merge: `7e7fd15` (Cycle 003 merged via PR #8)

Confirms Cycle 003 acceptance is present on `main` before CI Action work begins.

## Cycle 003 acceptance on main

| Check | Evidence |
|-------|----------|
| `dare-coaz-integrity` crate | `crates/dare-coaz-integrity/` |
| `validate coaz-integrity` CLI | `crates/dare-agent-security-cli/src/coaz_integrity.rs` |
| Seven built-in vectors | `vectors/coaz-mcp/authorization-integrity/v1/COAZ-INTEGRITY-*.json` |
| Cycle 003 PROOF | `DARE/cycles/003-coaz-authorization-integrity/PROOF.md` |
| Operator docs | `docs/coaz-integrity*.md` |

Cycle 003 is complete on this branch — proceed with Cycle 004.

## Workspace layout (confirmed)

```text
crates/dare-security-evidence/     # Cycle 001 evidence kernel (dependency leaf)
crates/dare-mcp-discovery/         # Cycle 002 passive discovery
crates/dare-coaz-integrity/        # Cycle 003 authorization integrity
crates/dare-agent-security-cli/    # bin: dare-agent-security
labs/synthetic-mcp/                # synthetic MCP lab (extend, do not fork)
```

MSRV: **1.88** (`Cargo.toml` workspace `rust-version`).

## CLI surface (non-interactive today)

| Command | Purpose | Key flags |
|---------|---------|-----------|
| `discover` | Passive MCP inventory | `--stdio`, `--url`, `--json`, `--evidence-dir`, `--target-id`, bounds |
| `validate coaz-integrity` | Offline integrity vectors | `--all`, `--fixture`, `--json`, `--reference-mode`, `--evidence-dir` |

Package: `dare-agent-security` (`crates/dare-agent-security-cli/Cargo.toml`).

Exit codes: [`crates/dare-agent-security-cli/EXIT.md`](../../crates/dare-agent-security-cli/EXIT.md).

**Gap for Cycle 004:** no aggregate CI result file, no GitHub Action adapter, no unified `--output-dir` across commands — task-002/004 address this.

## Evidence contract

- Schema: `schemas/evidence/v1/evidence.schema.json` (Cycle 001, unchanged)
- Discovery bridge extension: `dare.mcp.discovery` (`dare-mcp-discovery`)
- Integrity bridge extension: `dare.coaz.integrity` (`dare-coaz-integrity`)
- Example fixtures: `examples/evidence/`, `examples/coaz-integrity/evidence/`

## Synthetic fixtures (reuse for Action E2E)

| Source | Use in Cycle 004 |
|--------|------------------|
| `labs/synthetic-mcp` | `discover --stdio` PASS path (task-007) |
| `vectors/coaz-mcp/authorization-integrity/v1/` | `validate coaz-integrity` secure/vulnerable matrix |
| `examples/coaz-integrity/secure|vulnerable/` | Contract round-trip references |

Do not create a second competing lab.

## Current CI

- `.github/workflows/ci.yml` — fmt, clippy, test, cargo audit
- No composite/container Action yet — task-005 creates `action.yml`

## Documentation drift (task-010)

| Location | Issue |
|----------|-------|
| `README.md` § Next steps | Still mentions "finish human review/merge of Cycle 002" — Cycle 002/003 are merged |
| `DARE/AGENT-WORKFLOW.md` | Already points to Cycle 004 |
| No `ROADMAP.md` | Optional; Cycle 004 docs may add Action roadmap section |

## Task path map (002–011)

| Task | Primary paths |
|------|----------------|
| 002 | `schemas/ci/v1/` or `crates/dare-agent-security-cli/src/ci_result.rs` (contract TBD in task-002) |
| 003 | `DARE/cycles/004-ci-security-gate/ARCHITECTURE.md` or `action/THREAT-MODEL.md` |
| 004 | `crates/dare-agent-security-cli/src/{ci,aggregate}*.rs` |
| 005 | `action/action.yml`, `action/Dockerfile`, `action/entrypoint.sh` |
| 006 | `action/entrypoint.sh` (GITHUB_OUTPUT, STEP_SUMMARY) |
| 007 | `fixtures/ci/` or extend `examples/` + vector refs |
| 008 | `.github/workflows/action-e2e.yml` |
| 009 | `action/tests/` or `crates/dare-agent-security-cli/tests/hostile_*.rs` |
| 010 | `docs/ci-gate.md`, README reconciliation |
| 011 | `DARE/cycles/004-ci-security-gate/PROOF.md` |

## Action packaging direction (from DESIGN, pending task-003 lock)

Primary candidate: **Docker container action** building `dare-agent-security` from this repo. Action invokes CLI only — zero duplicated domain logic.
