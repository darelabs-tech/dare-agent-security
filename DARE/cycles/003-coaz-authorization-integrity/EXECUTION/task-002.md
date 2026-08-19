# task-002 — Implement Portable Vector and Result Contracts

> Status: **READY FOR REVIEW**
> Depends on: task-001

## Objective

Create stable, versioned machine-readable contracts for authorization-integrity test definitions and execution results.

## Target artifacts

```text
schemas/vectors/coaz-integrity/v1/vector.schema.json
schemas/vectors/coaz-integrity/v1/result.schema.json
vectors/coaz-mcp/authorization-integrity/v1/
examples/coaz-integrity/
```

## Requirements

- Rust models mirror public JSON contracts;
- schema major `v1` is explicit;
- unsupported major fails closed;
- standards references distinguish normative draft/spec from upstream issue proposal;
- expected/observed/verdict combinations receive semantic validation;
- public schema contains no raw token/Authorization/API-key/private-key fields;
- fixtures are synthetic only.

## Tests

- valid vector/result round trips;
- invalid schema major rejected;
- missing vector id/standards/expected state rejected;
- incoherent verdict rejected;
- additional secret-bearing prohibited fields rejected where contract can enforce them;
- offline JSON Schema validation.

## DONE when

Portable vector definitions and result records are deterministic, offline-validatable and independent of the generic evidence schema.
