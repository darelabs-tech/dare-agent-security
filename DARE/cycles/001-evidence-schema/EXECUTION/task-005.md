# task-005 — Implement redaction safety and secret-safe errors

> Cycle: `001-evidence-schema`
> Status: DONE
> Depends on: `task-002`
> Complexity: HIGH

## Objective

Implement the contract-level protections that prevent accidental serialization or disclosure of representative credential material through supported evidence fields.

## Required implementation

1. Make `RedactionMetadata` mandatory for valid top-level evidence.
2. Validate coherence between `applied`, `strategy`, and redacted field metadata.
3. Add detection for high-risk key names in generic attribute/extension maps where supported, including representative forms of:
   - password;
   - secret;
   - token;
   - api_key;
   - private_key;
   - authorization.
4. Ensure public error messages never echo rejected sensitive values.
5. Provide redaction/sanitization helpers only where they are deterministic and contract-safe.

## Security requirements

- Detection is defense-in-depth, not a promise of complete secret discovery.
- Do not log raw rejected values in tests or error display output.
- Do not create a general-purpose secrets scanner in this cycle.
- `NONE_REQUIRED` must mean a producer explicitly determined that no redaction was needed, not that redaction was skipped.

## Tests

Add negative tests with synthetic values proving representative credential material cannot be serialized through supported generic maps without rejection/sanitization.

Cover:

- bearer-like token value;
- password field;
- API key field;
- private-key-like field;
- authorization header-like field;
- safe non-secret metadata accepted;
- error display does not contain the secret input.

## Validation gates

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Done when

- redaction metadata semantics are enforced;
- representative raw secret material is blocked/sanitized according to the public contract;
- safe errors cannot leak rejected values;
- tests clearly document the heuristic boundary.

## Execution result

- Status: DONE
- Files: `crates/dare-security-evidence/src/redaction.rs`
- Notes: redaction metadata coherence enforced; high-risk keys and bearer/PEM/JWT-like values rejected in generic maps; error Display never includes the rejected secret. Heuristics are defense-in-depth only.
