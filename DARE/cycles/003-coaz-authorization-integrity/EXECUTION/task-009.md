# task-009 — Implement Cycle 001 Evidence Bridge

> Status: **DONE**
> Depends on: task-002, task-008

## Objective

Emit generic Cycle 001 `SecurityEvidence` from each Cycle 003 vector result without adding COAZ-specific fields to the evidence kernel.

## Requirements

- evidence vector id equals portable vector id;
- expected/observed/verdict derive from validated vector result;
- reference mode and standards mapping are metadata/artifact references where supported;
- result JSON is referenced by stable path/digest;
- redaction runs before evidence serialization;
- stale-permit forwarding maps to FAIL;
- harness infrastructure failure maps to ERROR, not FAIL/PASS;
- insufficient deterministic projection maps to INCONCLUSIVE.

## Tests

- PASS evidence fixture;
- FAIL evidence fixture;
- INCONCLUSIVE fixture;
- ERROR fixture;
- Cycle 001 JSON Schema + semantic validation;
- canary secret absence.

## DONE when

Cycle 003 findings are first-class evidence consumers while Cycle 001 remains standards-neutral.
