# Cycle 005 — Implementation Notes (task-001 reconciliation)

> Generated: 2026-08-20
> Branch: `agent/cycle-005-synthetic-mcp-security-lab`
> Baseline merge: `b9860a4` (Cycle 004 merged via PR #9)

Confirms Cycle 004 acceptance is present on `main` before synthetic lab corpus work begins.

## Cycle 004 acceptance on main

| Check | Evidence |
|-------|----------|
| Cycle 004 PROOF | `DARE/cycles/004-ci-security-gate/PROOF.md` |
| Action metadata | `action.yml` (`runs.image: Dockerfile` at repo root) |
| Docker packaging | `Dockerfile`, `action/entrypoint.sh`, `.dockerignore` |
| CI result contract | `schemas/ci/v1/ci-result.schema.json`, `docs/ci-result-contract.md` |
| Operator docs | `docs/ci-gate.md`, `action/ARCHITECTURE.md`, `action/THREAT-MODEL.md` |
| Action E2E | `.github/workflows/action-e2e.yml` (`uses: ./`) |
| Synthetic Action fixtures | `fixtures/ci/matrix.json` |

Cycle 004 is complete on this branch — proceed with Cycle 005.

## Workspace layout (confirmed)

```text
crates/dare-security-evidence/     # Cycle 001 evidence kernel
crates/dare-mcp-discovery/         # Cycle 002 passive discovery
crates/dare-coaz-integrity/        # Cycle 003 authorization integrity
crates/dare-agent-security-cli/    # bin: dare-agent-security (+ lib dare_agent_security)
labs/synthetic-mcp/                # Cycle 002 vehicle-rental lab (extend — do not fork)
```

MSRV: **1.88** (`Cargo.toml` workspace `rust-version`).
rmcp: **3.1.3** (workspace dependency).

## CLI surface (non-interactive)

| Command | Purpose | Key flags |
|---------|---------|-----------|
| `discover` | Passive MCP inventory | `--stdio`, `--url`, `--json`, `--evidence-dir`, `--output-dir`, `--fail-on-inconclusive`, `--target-id`, bounds |
| `validate coaz-integrity` | Offline integrity vectors | `--all`, `--fixture`, `--json`, `--reference-mode`, `--evidence-dir`, `--output-dir`, `--fail-on-inconclusive` |
| `ci write-result` | Aggregate CI result without domain logic | `--mode`, `--output-dir`, `--fail-on-inconclusive`, `--target-label` |

Package: `dare-agent-security` (`crates/dare-agent-security-cli/`).

Exit codes: [`crates/dare-agent-security-cli/EXIT.md`](../../../crates/dare-agent-security-cli/EXIT.md).

CI artifacts under `--output-dir`:

- `ci-result.json`
- `summary.md`
- `github-output.env`
- `evidence/*.json`

## Evidence / CI contracts (reuse — do not fork)

| Contract | Path |
|----------|------|
| Evidence v1 | `schemas/evidence/v1/evidence.schema.json` |
| Discovery inventory | `schemas/discovery/v1/inventory.schema.json` |
| COAZ integrity vector/result | `schemas/vectors/coaz-integrity/v1/` |
| CI aggregate result | `schemas/ci/v1/ci-result.schema.json` |
| Verdict vocabulary | `PASS`, `FAIL`, `INCONCLUSIVE`, `ERROR` (Cycle 001) |

Integrity bridge: `dare.coaz.integrity` via `dare-coaz-integrity`.
Discovery bridge: `dare.mcp.discovery` via `dare-mcp-discovery`.

**Cycle 005 must not invent a second evidence, integrity, or CI result model.**

## Cycle 004 Action / CI gate

| Input | Values |
|-------|--------|
| `mode` | `discover` \| `validate` |
| `target` | aliases (`secure-pass`, `fail-stale-permit`, `inconclusive-empty`, `synthetic-mcp`, …) or fixture ids |
| `output-dir` | default `.dare-agent-security` |
| `fail-on-inconclusive` | default `true` |
| `reference-mode` | `secure` \| `vulnerable` |

Outputs: `verdict`, `evidence-path`, `summary-path`.

Workflows:

- `.github/workflows/ci.yml` — fmt, clippy, test, cargo audit
- `.github/workflows/action-e2e.yml` — Action matrix (PASS/FAIL/INCONCLUSIVE/ERROR)

task-010 must integrate the lab corpus through this gate with:

```text
expected FAIL + observed FAIL = scenario assertion PASS
```

## Existing synthetic lab (`labs/synthetic-mcp`)

| Item | Detail |
|------|--------|
| Binary | `synthetic-mcp` (stdio default; `--http 127.0.0.1:0` for loopback) |
| Domain | fictional vehicle-rental MCP |
| Protocol | primary `2026-07-28` (`server/discover`); also exercises legacy `2024-11-05` |
| Modules | `server.rs`, `catalog.rs`, `http.rs`, `trace.rs` |
| Docs | `docs/synthetic-lab.md` |

**Direction for Cycle 005:** extend this lab / add scenario packages under a shared framework — do not create a competing second lab tree that duplicates discovery/integrity engines.

## MCP SDK / protocol support

- Client (discovery): `rmcp` 3.1.3 with stdio + streamable HTTP
- Server (lab): `rmcp` server features in `labs/synthetic-mcp`
- Passive policy: list-only — no `tools/call` / `resources/read` / `prompts/get` in default discover

## Test conventions

- Workspace: `cargo test --workspace`
- CLI integration tests under `crates/dare-agent-security-cli/tests/`
- Crate unit/integration tests colocated (`tests/` + `src/` `#[cfg(test)]`)
- Gates: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
- Temp dirs via `tempfile` where needed

## Documentation drift (task-012)

| Location | Issue |
|----------|-------|
| `README.md` § Stage | Mentions Cycles 001–004; does not yet list Cycle 005 as current work |
| `README.md` § priorities | Still prioritizes hardening Cycle 004 Action; lab corpus not listed |
| `DARE/AGENT-WORKFLOW.md` | Already points to Cycle 005 |
| No scenario catalog yet | task-012 deliverable |

## Task path map (002–012)

| Task | Primary paths (proposed) |
|------|---------------------------|
| 002 | `schemas/lab/v1/scenario.schema.json` + `crates/dare-mcp-lab` |
| 003 | `crates/dare-mcp-lab` framework (`LabSession`, identities, credentials) |
| 004 | scenarios MCP-LAB-001, MCP-LAB-002 |
| 005 | MCP-LAB-003 confused deputy |
| 006 | MCP-LAB-004/005/006 — reuse `dare-coaz-integrity` |
| 007 | MCP-LAB-007/008/009 |
| 008 | MCP-LAB-010 MRTR |
| 009 | `crates/dare-mcp-lab/src/harness.rs` scenario runner |
| 010 | `.github/workflows/ci.yml` job `lab-corpus` |
| 011 | `tests/hostile_fixtures.rs` |
| 012 | `docs/mcp-security-lab.md`, catalog, `PROOF.md` |

## Gaps for Cycle 005 (not blockers)

1. No versioned scenario manifest schema yet (task-002).
2. Current lab is a single rental target — no secure/vulnerable scenario matrix (tasks 004–008).
3. No thin scenario runner that maps expected vs observed evidence (task-009).
4. Action E2E matrix is Action-fixture oriented, not full MCP-LAB corpus (task-010).

None of these contradict Cycles 001–004 contracts. Proceed.
