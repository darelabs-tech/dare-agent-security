# Cycle 008 — Implementation Notes (task-001 reconciliation)

> Generated: 2026-08-20
> Branch: `agent/cycle-008-agent-attack-graph-mvp`
> Baseline merge: `ee4428e` (Cycle 007 merged via PR #13)

Confirms Cycles 001–007 contracts on `main` before Agent Attack Graph MVP work.

## Baseline on main

| Cycle | Evidence |
|-------|----------|
| 001 | `crates/dare-security-evidence/`, `schemas/evidence/v1/` — Verdict PASS/FAIL/INCONCLUSIVE/ERROR; redaction |
| 002 | `crates/dare-mcp-discovery/`, `schemas/discovery/v1/` — `discover` inventory |
| 003 | `crates/dare-coaz-integrity/`, `vectors/coaz-mcp/` — `validate coaz-integrity` |
| 004 | `action.yml`, `schemas/ci/v1/ci-result.schema.json` (closed), `ci write-result` |
| 005 | `crates/dare-mcp-lab/`, `labs/scenarios/MCP-LAB-001..010` — synthetic ground truth |
| 006 | `crates/dare-coverage/`, `schemas/coverage/v1/registry.json`, `profiles/mcp-security-baseline.json` |
| 007 | `crates/dare-benchmark/`, `schemas/benchmark/v1/`, `validate benchmark` — optional graph input |

MSRV **1.88**. rmcp **3.1.3**. CLI package `dare-agent-security`.

## Reuse — do not fork

| Concern | Reuse |
|---------|-------|
| Verdict | Cycle 001 `Verdict` (never as edge evidence status) |
| CoverageStatus / plan / report | Cycle 006 `dare-coverage` |
| Property registry IDs | `schemas/coverage/v1/registry.json` |
| Canonical digests | Cycle 006/007 key-sorted JSON → SHA-256 |
| Redaction / secret safety | Cycle 001 `validate_secret_safety` patterns |
| Lab fixtures | Cycle 005 corpus as optional fact sources |
| BenchmarkRecord | Optional provenance input only |
| CI aggregate | Cycle 004 `ci-result.json` stays closed; graph emits sibling artifacts |

**Cycle 008 must not invent a second evidence, verdict, coverage, property, or benchmark engine.**

## Edge evidence ≠ verdict

```text
OBSERVED | STATICALLY_PROVEN | INFERRED | NOT_TESTED
```

These are path/edge evidence states. They must never be serialized as PASS/FAIL.

## Paths for tasks 002–018

| Task | Intended location |
|------|-------------------|
| 002 | `schemas/attack-graph/v1/attack-graph.schema.json` |
| 003 | `crates/dare-attack-graph/src/node.rs` — taxonomy + stable IDs |
| 004 | `crates/dare-attack-graph/src/edge.rs` — taxonomy + edge digests |
| 005 | `crates/dare-attack-graph/src/authority.rs` |
| 006 | `crates/dare-attack-graph/src/evidence.rs` |
| 007 | `crates/dare-attack-graph/src/facts.rs` — Graph Fact Extractor |
| 008 | `crates/dare-attack-graph/src/builder.rs` |
| 009 | `crates/dare-attack-graph/src/mapping.rs` + builtin property→graph map |
| 010 | `crates/dare-attack-graph/src/path.rs` — bounded engine |
| 011 | path status + impact factors (same module / `impact.rs`) |
| 012 | `crates/dare-attack-graph/src/provenance.rs` |
| 013 | `crates/dare-attack-graph/src/render.rs` — Mermaid/DOT |
| 014 | `fixtures/attack-graph/` synthetic scenarios |
| 015 | `crates/dare-attack-graph/tests/adversarial.rs` |
| 016 | CLI `validate attack-graph` |
| 017 | CI job `attack-graph-mvp` |
| 018 | `docs/attack-graph.md` + `PROOF.md` |

## CLI direction

```text
dare-agent-security validate attack-graph \
  --facts <path> \
  --output-dir <path> \
  --max-depth <n> \
  --max-paths <n>
```

Thin orchestration. No autonomous path execution. Analysis artifacts only.

## Safety freeze

```text
analysis and graph derivation only
NOT autonomous exploitation (Cycle 009)
credentials as logical node IDs only
bounded traversal mandatory
inferred edges remain visibly INFERRED
```

## Invariants for later tasks

- Identical facts → identical graph digest.
- OBSERVED/STATICALLY_PROVEN require `evidence_ids`.
- INFERRED requires `rationale` + `source_facts`.
- NOT_TESTED requires `reason`.
- Unbounded path search is a hard error.
- No secret material in node/edge labels.
