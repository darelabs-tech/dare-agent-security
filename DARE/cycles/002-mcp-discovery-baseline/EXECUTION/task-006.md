# task-006 — Deterministic tool classification

> Status: DONE
> Depends on: task-002
> Complexity: HIGH

## Objective
Classify tool behavior conservatively and explainably without LLM judgment.

## Classes
`READ_ONLY`, `STATE_CHANGING`, `DESTRUCTIVE`, `UNKNOWN`.

## Required implementation
- central pure classification function;
- provenance recorded for every result;
- explicit trusted configuration/defined protocol metadata takes precedence;
- destructive semantics dominate weaker signals;
- ambiguous or insufficient metadata => `UNKNOWN`;
- name/description heuristics, if implemented, are recorded only as non-authoritative indicators and cannot independently produce a safe classification.

## Tests
Table-driven coverage for all classes, conflicting signals, missing annotations and ambiguous descriptions. Random input ordering must not alter result.

## Security invariants
No LLM-as-judge. No classification may convert uncertainty into `READ_ONLY` merely from naming conventions.

## DONE when
Classification is deterministic, provenance-rich and all ambiguous fixtures resolve to `UNKNOWN` unless an approved authoritative rule applies.

---

## Execution result

- **Status:** DONE
- **Date:** 2026-08-18
- **Files:** `crates/dare-mcp-discovery/src/classification.rs`, `tests/classification.rs`
- **Rules:** explicit config wins; destructive dominates; name heuristics cannot independently produce READ_ONLY
