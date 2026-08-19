# task-002 — Discovery Inventory v1 model and JSON Schema

> Status: DONE
> Depends on: task-001
> Complexity: HIGH

## Objective
Define the canonical, versioned machine-readable discovery inventory.

## Required implementation
- Rust domain types for server/protocol/transport/auth/tools/resources/templates/prompts/indicators/warnings/redaction/hashes;
- `schemas/discovery/v1/inventory.schema.json`;
- `examples/discovery/complete.json` and `partial.json`;
- structural + semantic validation;
- unsupported schema major fails closed;
- deterministic normalization/ordering contract.

## Security invariants
- no credential-bearing public field;
- target identity is safe/sanitized;
- partial vs complete state is explicit;
- unknown fields/enums fail according to v1 compatibility policy.

## Tests
Valid fixtures round-trip and validate offline. Negative tests cover missing IDs, invalid version, incoherent partial state, malformed digest/timestamp, unknown enum and forbidden fields.

## Gates
Workspace Rust gates plus offline JSON Schema validation.

## DONE when
Both public fixtures validate structurally and semantically and invalid corpus fails for the intended reasons.

---

## Execution result

- **Status:** DONE
- **Date:** 2026-08-18
- **Files:** `crates/dare-mcp-discovery/src/inventory*.rs`, `tests/inventory_*.rs`, `schemas/discovery/v1/inventory.schema.json`, `examples/discovery/{complete,partial}.json`
- **Gates:** workspace fmt/clippy/test passed after merge with task-003
