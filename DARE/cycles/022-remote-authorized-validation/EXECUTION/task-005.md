# task-005 — Validate every record in all 9 engine evidence bridges

**Status:** DONE  
**Complexity:** MED

## Files changed

- `crates/dare-{a2a,identity,mcp-auth,memory,rag,supply-chain,tool}-security/src/evidence_bridge.rs`, `crates/dare-prompt-injection/src/evidence_bridge.rs`: each calls `dare_security_evidence::validate(&evidence)` right after `validate_secret_safety`, and maps the error to the crate's existing refusal constructor
- `crates/dare-multi-turn-security/src/{evidence_bridge.rs,error.rs}`: new variant `MultiTurnError::EvidenceInvalid`. It is not a refusal, because it is an engine fault, and it is covered by the existing every-variant message test

## Proof of fail-closed

- `every_engine_bridge_validates_before_returning` (`crates/dare-agent-security-cli/tests/every_bridge_validates.rs`) reads all nine bridge sources and asserts that the production part calls the validator and propagates the error with `?`.
- The validator's own rejection of inconsistent records is covered in `dare-security-evidence`, for example `contradictory_pass_is_rejected`.

This replaces the planned per-bridge "deliberately inconsistent record" unit test. The
builders construct their records internally, so an inconsistent record cannot be
injected without adding a test-only seam to nine frozen crates.

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- `cargo test --workspace`: 281 suites, 3 957 passed, 0 failed (baseline 3 955 + 2 new tests)
- No dependency change, so no audit was required
