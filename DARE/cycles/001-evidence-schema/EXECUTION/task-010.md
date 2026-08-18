# task-010 — Prove Cycle 001 evidence contract end to end

> Cycle: `001-evidence-schema`
> Status: DONE
> Depends on: `task-009`
> Complexity: HIGH

## Objective

Execute the final acceptance proof for Cycle 001. This task must not add new product capability; it verifies that the approved Design and Blueprint have been implemented without weakening security properties.

## End-to-end proof

Demonstrate the complete path:

```text
synthetic vector inputs
        -> canonical Rust model
        -> deterministic comparison
        -> verdict derivation/validation
        -> safe evidence serialization
        -> JSON Schema validation
        -> semantic validation
        -> round-trip persistence
```

## Required proofs

Prove all of the following:

1. A supported v1 evidence record validates structurally and semantically.
2. An unsupported schema major version fails closed.
3. A contradictory verdict is rejected.
4. Representative raw secret material cannot be emitted through supported public fields without rejection/sanitization.
5. PASS fixture behaves according to documented PASS semantics.
6. FAIL fixture behaves according to documented FAIL semantics.
7. INCONCLUSIVE fixture is never interpreted as PASS.
8. ERROR fixture is never interpreted as PASS or FAIL security outcome.
9. JSON Schema validation requires no network access.
10. Generic evidence validation requires no MCP/AuthZEN/COAZ dependency.
11. Public fixtures survive the full round-trip compatibility test.
12. No customer-derived or proprietary data exists in fixtures/tests.

## Required gates

Run and record success for:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Also confirm:

- canonical JSON Schema self-validates;
- all public fixtures validate;
- all required negative cases fail for intended reasons;
- CI configuration reflects the same quality gates.

## Review checklist

Before marking DONE:

- [ ] No raw credential field exists.
- [ ] Redaction metadata is mandatory.
- [ ] Verdict contradictions are rejected.
- [ ] Unknown schema major versions fail closed.
- [ ] Errors do not echo secret values.
- [ ] No protocol-specific requirement leaked into the generic evidence contract.
- [ ] No customer-specific concept was added.
- [ ] Validation is offline-capable.
- [ ] JSON Schema is independently usable by non-Rust consumers.
- [ ] No TODO/FIXME/stub remains in production code.

## Completion record

When all proofs pass, update the cycle status artifacts according to the DARE workflow and reference the implementation PR/commit used for the proof.

Do not mark Cycle 001 complete if any gate is bypassed, muted, skipped or weakened merely to obtain a green result.

## Done when

Cycle 001 has reproducible evidence that the public v1 deterministic security evidence contract satisfies the approved Design, Blueprint, TASKS and security invariants end to end.

## Execution result

- Status: DONE
- Files: `crates/dare-security-evidence/tests/e2e_proof.rs`
- Gates: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
- Proofs: v1 validates; unknown major fails closed; contradictory PASS rejected; representative secrets rejected without echo; PASS/FAIL/INCONCLUSIVE/ERROR fixtures keep semantics; schema/docs/CI exist; no protocol-specific core coupling.
- Cycle remains APPROVED FOR EXECUTION until human/DARE review marks the cycle DONE.
