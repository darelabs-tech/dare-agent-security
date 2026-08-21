# Cycle 011 — Implementation Notes (task-001 reconciliation)

> Generated: 2026-08-21
> Branch: `agent/cycle-011-productization-v1-release-readiness`
> Baseline merge: `174d92a` (Cycle 010 merged via PR #16)

Confirms Cycles 001–010 contracts on `main` before Productization & v1.0 Release Readiness work.

## Baseline on main

| Cycle | Evidence |
|-------|----------|
| 001 | `crates/dare-security-evidence/`, `schemas/evidence/v1/` |
| 002 | `crates/dare-mcp-discovery/` — `discover` |
| 003 | `crates/dare-coaz-integrity/` — `validate coaz-integrity` |
| 004 | `action.yml`, `schemas/ci/v1/ci-result.schema.json` (closed) |
| 005 | `crates/dare-mcp-lab/`, `labs/scenarios/` |
| 006 | `crates/dare-coverage/`, `schemas/coverage/v1/registry.json` |
| 007 | `crates/dare-benchmark/`, `validate benchmark` |
| 008 | `crates/dare-attack-graph/`, `validate attack-graph` |
| 009 | `crates/dare-adversarial/`, `validate adversarial` — ROE/budget/kill switch |
| 010 | `crates/dare-continuous/`, `validate continuous` — CORE FEATURE FREEZE in `PROOF.md` |

MSRV **1.88**. rmcp **3.1.3**. CLI package / binary `dare-agent-security`.

## Reuse — do not fork

| Concern | Reuse |
|---------|-------|
| Verdict / evidence | Cycle 001 |
| Discovery / inventory | Cycle 002 |
| COAZ integrity | Cycle 003 |
| CI aggregate | Cycle 004 `ci-result.json` stays closed |
| Lab corpus | Cycle 005 |
| Coverage / properties | Cycle 006 |
| Benchmark methodology | Cycle 007 |
| Attack graph / paths | Cycle 008 |
| Adversarial validation | Cycle 009 runner/ROE (never weaken) |
| Continuous revalidation / drift | Cycle 010 |

**Cycle 011 must not invent a second evidence, verdict, coverage, property, graph, path, adversarial, or continuous engine.** Product layer orchestrates 001–010 only.

## Safety / product freeze inherited from Cycle 010

```text
CORE FEATURE FREEZE remains in force for security engines
AUTHORIZED_DYNAMIC remains ROE-gated (Cycle 009 authoritative)
confidential/offline fail-closed — no telemetry / prohibited egress
safe defaults remain static/passive/plan-only unless explicitly changed
```

## Paths for tasks 002–025

| Task | Intended location |
|------|-------------------|
| 002 | `docs/product/v1-contract.md` + `schemas/product/v1/` public contract notes |
| 003 | packaging: `Cargo.toml` versioning, install docs, optional binary alias notes |
| 004 | CLI `init` — `crates/dare-agent-security-cli/src/product/init.rs` |
| 005 | `schemas/product/v1/config.schema.json` + config loader |
| 006 | CLI `assess` orchestrating discover/coverage/graph/continuous as needed |
| 007 | privacy policy + `--confidential` / `--offline` flags (fail-closed) |
| 008 | egress/telemetry denial tests under `crates/dare-product/tests/` or CLI tests |
| 009 | product redaction layer reusing discovery sanitize + report filters |
| 010 | product result / view model in `crates/dare-product/` |
| 011 | Executive HTML renderer → `.dare-security/runs/<id>/reports/executive.html` |
| 012 | Technical HTML renderer → `reports/technical.html` |
| 013 | `schemas/product/v1/{findings,summary,coverage}.schema.json` |
| 014 | classification metadata on reports |
| 015 | CLI `doctor` diagnostics |
| 016 | categorized errors + documented exit codes (extend `EXIT.md`) |
| 017 | `examples/{vulnerable-mcp,secure-mcp,agentic-demo}/` |
| 018 | `docs/quickstart.md` (install → fix → reassess journey) |
| 019 | `docs/product/` user docs + privacy/data handling |
| 020 | performance baseline notes/tests (no new scale subsystem) |
| 021 | release hardening tests (path traversal, HTML injection, offline escape) |
| 022 | release automation scripts/workflow for package + checksums |
| 023 | clean-environment acceptance harness (container/script) |
| 024 | external-operator usability checklist evidence |
| 025 | `PROOF.md` + v1.0 release-gate decision |

## Product CLI direction (public contract)

Preferred UX maps onto the existing binary without a second security engine:

```text
dare-agent-security init
dare-agent-security assess <path> [--confidential] [--offline]
dare-agent-security report [--run <id>]
dare-agent-security doctor
```

Existing `discover` / `validate *` / `ci` remain available for power users and CI. Product commands orchestrate them.

## Artifact layout (reconciled)

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

Aligns with Design §13; keeps Cycle 004 `ci-result.json` closed (sibling artifacts only).

## Invariants for later tasks

- No new major security capability after CORE FEATURE FREEZE.
- Confidential/offline must be testably fail-closed.
- Renderers never receive raw secret values.
- Clean-environment acceptance is mandatory for v1.0 gate.
- Do not pre-design Cycle 012.
