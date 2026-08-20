# Cycle 007 — Implementation Notes (task-001 reconciliation)

> Generated: 2026-08-20
> Branch: `agent/cycle-007-mcp-security-benchmark-corpus-methodology`
> Baseline merge: `306a260` (Cycle 006 merged via PR #11/#12)

Confirms Cycles 001–006 contracts on `main` before benchmark methodology work.

## Baseline on main

| Cycle | Evidence |
|-------|----------|
| 001 | `crates/dare-security-evidence/`, `schemas/evidence/v1/` — Verdict PASS/FAIL/INCONCLUSIVE/ERROR |
| 002 | `crates/dare-mcp-discovery/`, `schemas/discovery/v1/` — `discover` |
| 003 | `crates/dare-coaz-integrity/`, `vectors/coaz-mcp/` — `validate coaz-integrity` |
| 004 | `action.yml`, `schemas/ci/v1/ci-result.schema.json` (closed), `ci write-result` |
| 005 | `crates/dare-mcp-lab/`, `labs/scenarios/MCP-LAB-001..010` — ground truth, not prevalence |
| 006 | `crates/dare-coverage/`, `schemas/coverage/v1/`, `profiles/mcp-security-baseline.json` |

MSRV **1.88**. rmcp **3.1.3**. CLI package `dare-agent-security`.

## Reuse — do not fork

| Concern | Reuse |
|---------|-------|
| Verdict | Cycle 001 `Verdict` |
| CoverageStatus / plan / report | Cycle 006 `dare-coverage` |
| Profile + registry digests | `profile_digest_sha256`, builtin registry |
| Lab ground truth | Cycle 005 corpus (controlled) |
| CI aggregate | Cycle 004 `ci-result.json` stays closed; benchmark emits sibling artifacts |

**Cycle 007 must not invent a second evidence, verdict, coverage, or profile engine.**

## Digest convention

Cycle 006 digests use SHA-256 over deterministic JSON serialization.
Cycle 007 corpus/run digests: recursive key-sorted JSON → SHA-256 hex (JCS-style), documented in methodology.

## Paths for tasks 002–016

| Task | Intended location |
|------|-------------------|
| 002 | `schemas/benchmark/v1/corpus-manifest.schema.json`, `crates/dare-benchmark/` |
| 003 | `schemas/benchmark/v1/benchmark-run.schema.json` |
| 004 | `schemas/benchmark/v1/benchmark-record.schema.json` |
| 005 | `crates/dare-benchmark/src/lineage.rs` |
| 006 | `docs/benchmark-methodology.md` (sampling) + selection module |
| 007 | `crates/dare-benchmark/src/eligibility.rs`, `aggregate.rs` |
| 008 | `crates/dare-benchmark/src/runner.rs` — STATIC/LOCAL_PASSIVE default |
| 009 | `benchmark/fixtures/hostile/`, `tests/hostile_runner.rs` |
| 010 | `crates/dare-benchmark/src/validation.rs` |
| 011 | `crates/dare-benchmark/src/disclosure.rs`, `docs/responsible-disclosure.md` |
| 012 | `benchmark/corpus/pilot-methodology-v1/` (25–50 fixture targets) |
| 013 | `aggregate.json` producer |
| 014 | CI job + fixture regression tests |
| 015 | methodology + interpretation docs |
| 016 | `PROOF.md` |

## CLI direction

```text
dare-agent-security validate benchmark --corpus <path> --output-dir <path>
```

Thin orchestration over schemas/math/runner. No top-level `benchmark` command required.
No network for security semantics in default modes.

## Safety freeze

```text
STATIC + LOCAL_PASSIVE by default
AUTHORIZED_DYNAMIC requires explicit opt-in + ROE flag
pilot corpus = methodology fixtures (no unauthorized remote infra)
no prevalence claims beyond documented denominators
```

## Invariants for later tasks

- Every target has commit SHA (40 hex).
- Lineage CANONICAL \| MATERIAL_FORK \| MIRROR \| VENDOR_COPY \| EXAMPLE.
- Property prevalence uses property-specific eligible denominators (Cycle 006).
- Publication export redacts secrets/exploit detail by default.
