# task-003 — Implement Semantic Normalization and Canonicalization

> Status: **READY FOR REVIEW**
> Depends on: task-001

## Objective

Define the deterministic semantic equality boundary used by authorization bindings.

## Requirements

- project-owned normalized JSON-like value type or equivalent explicit contract;
- object key order is irrelevant;
- array order remains significant;
- booleans, strings, null and numeric values normalize deterministically;
- non-finite numbers are rejected;
- raw whitespace/formatting is not security-significant;
- canonical serialization is stable across repeated runs;
- digest uses SHA-256 unless the repository already has a stronger approved convention.

## Required controls

```text
{"a":1,"b":2}
{"b":2,"a":1}
```

must produce the same semantic canonical form/digest.

A mapped value change must produce a different digest.

## Tests

- table-driven equivalence cases;
- inequality cases;
- nested object cases;
- numeric edge cases;
- repeatability across serialize/deserialize;
- canonical form contains no nondeterministic map iteration artifacts.

## DONE when

The binding engine can compare semantics without depending on raw JSON bytes.
