# task-006 — Implement deterministic outcome comparison and verdict consistency

> Cycle: `001-evidence-schema`
> Status: DONE
> Depends on: `task-002`, `task-004`
> Complexity: HIGH

## Objective

Implement the generic deterministic comparison boundary and enforce consistency between expected outcome, observed outcome and verdict.

## Required implementation

1. Define an `OutcomeComparator` abstraction equivalent to the approved Blueprint.
2. Implement a default exact comparator for generic fields only.
3. Define a typed `ComparisonResult`.
4. Provide a builder/factory path that derives verdict when deterministic comparison is available.
5. Validate caller-supplied/deserialized verdicts for consistency.

## Required semantics

- `PASS`: deterministic agreement.
- `FAIL`: deterministic mismatch.
- `INCONCLUSIVE`: evidence insufficient for deterministic agreement/mismatch.
- `ERROR`: evaluation infrastructure/interaction failure, not a security success/failure.

The library must reject contradictory records, including:

```text
expected = DENY
observed = ALLOW
verdict = PASS
```

## Architectural constraints

- Do not implement COAZ/MCP semantic comparison here.
- Do not call an LLM to determine comparison.
- Do not infer severity from verdict.
- The comparator must be deterministic for equal inputs.

## Tests

Cover:

- exact match -> PASS;
- deterministic mismatch -> FAIL;
- contradictory caller verdict rejected;
- INCONCLUSIVE cannot masquerade as PASS;
- ERROR cannot masquerade as FAIL/PASS;
- comparator determinism over repeated execution.

## Validation gates

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Done when

- generic comparison and verdict derivation are implemented;
- contradictory evidence cannot pass semantic validation;
- all four verdict semantics are tested;
- protocol-specific comparison remains outside the evidence crate.

## Execution result

- Status: DONE
- Files: `crates/dare-security-evidence/src/comparison.rs`
- Notes: `ExactOutcomeComparator`, `ComparisonResult`, `derive_verdict`, `apply_derived_verdict`; contradictory PASS and INCONCLUSIVE/ERROR masquerading as PASS/FAIL are rejected.
