# task-005 — Bounded enumeration engine

> Status: DONE
> Depends on: task-002, task-004
> Complexity: HIGH

## Objective
Enumerate passive MCP catalogs safely and deterministically.

## Required implementation
Enumerate tools, resources, resource templates and prompts with cursor pagination, deterministic normalization and structured partial outcomes.

Required bounds:
- max pages per collection;
- max items per collection;
- max response bytes;
- max schema depth;
- per-request timeout;
- overall timeout;
- repeated-cursor detection.

## Security invariants
- never dereference discovered resource URIs;
- never fetch prompt bodies;
- never dereference external JSON Schema `$ref` values;
- limit exhaustion yields typed warning/partial state rather than unbounded work.

## Tests
Multi-page success, repeated cursor, each configured bound, malformed page/cursor and partial-result determinism.

## DONE when
All four catalogs enumerate within bounds, partial results remain valid Inventory v1 records, and no content-fetch/action method is sent.

---

## Execution result

- **Status:** DONE
- **Files:** `enumerate.rs`, `enumerate_loop.rs`, `enumerate_schema.rs`, `tests/enumerate.rs`
- **Proof:** list methods only; COMPLETE vs PARTIAL; repeated cursor; bound tests
