# task-043 — MCPAuthSecurityResult and evidence bridge

**Status:** DONE - REVIEW PASS

Implement the bounded Cycle 018 result artifact and Cycle 001 evidence bridge with expected-vs-observed semantics, evidence digests, redaction metadata and PASS/FAIL/INCONCLUSIVE/ERROR precedence.

## Evidence

`src/result.rs` and `src/evidence_bridge.rs`. Precedence ERROR over FAIL over INCONCLUSIVE over PASS, with an observed violation outranking a later harness failure. `stop_on_first_fail` pushes the trial record before stopping, so the evidence that caused the stop is never lost to it. Evidence reuses the Cycle 001 contract, targets only the synthetic lab, carries cycle specifics in exactly one namespaced extension, and passes Cycle 001's own `validate_secret_safety` before being returned.
