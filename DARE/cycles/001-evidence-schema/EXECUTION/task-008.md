# task-008 — Implement contract, round-trip and negative security tests

> Cycle: `001-evidence-schema`
> Status: PENDING
> Depends on: `task-003`, `task-004`, `task-005`, `task-006`, `task-007`
> Complexity: HIGH

## Objective

Create the compatibility and negative-security test suite that proves the public evidence contract behaves deterministically and fails safely.

## Required implementation

For every public fixture:

1. deserialize JSON;
2. validate against the canonical JSON Schema;
3. validate semantic invariants;
4. serialize back to JSON;
5. deserialize again;
6. assert semantic equality.

Create invalid test cases covering at minimum:

- unsupported major schema version;
- missing vector identifier;
- contradictory `PASS`;
- `ERROR` without required error context;
- invalid timestamp ordering;
- representative raw authorization/token content;
- invalid verdict enum;
- malformed digest;
- forbidden unknown top-level field.

## Test quality requirements

- Each negative case must fail for the intended reason.
- Avoid brittle string-only error assertions where typed variants are available.
- No test may require network access.
- No test may contain real customer data or credentials.
- Regression tests should be added for any implementation defect found while executing the task.

## Suggested organization

```text
crates/dare-security-evidence/tests/
  contract.rs
  negative.rs
```

Exact layout may vary.

## Validation gates

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Done when

- all public fixtures pass the full contract pipeline;
- all required invalid cases fail safely and intentionally;
- round-trip compatibility is proven;
- the suite can serve as a compatibility gate for later schema changes.
