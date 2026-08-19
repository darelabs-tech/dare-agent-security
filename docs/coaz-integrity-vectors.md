# COAZ integrity — vector matrix and traces

Seven built-in vectors ship under
[`vectors/coaz-mcp/authorization-integrity/v1/`](../vectors/coaz-mcp/authorization-integrity/v1/).
All use the fictional `rental.quote` synthetic domain and in-process fixtures.

## Vector matrix

| ID | Title | Mutation | Expected enforcement (secure) | Projector |
|---|---|---|---|---|
| COAZ-INTEGRITY-001 | Unchanged `tools/call` after permit | `NONE` | `FORWARD_WITH_EXISTING_PERMIT` | default-tools-call |
| COAZ-INTEGRITY-002 | Mapped tool name changed | `TOOL_NAME` | `REEVALUATE_OR_REFUSE` | default-tools-call |
| COAZ-INTEGRITY-003 | Mapped argument changed | `MAPPED_ARGUMENT` | `REEVALUATE_OR_REFUSE` | declared-rental-quote |
| COAZ-INTEGRITY-004 | MCP method changed | `METHOD` | `REEVALUATE_OR_REFUSE` | default-tools-call |
| COAZ-INTEGRITY-005 | Mapped trusted context changed | `TRUSTED_CONTEXT` | `REEVALUATE_OR_REFUSE` | default-tools-call |
| COAZ-INTEGRITY-006 | JSON key order / formatting only | `JSON_REORDER_ONLY` | `PERMIT_REMAINS_BOUND` | declared-rental-quote |
| COAZ-INTEGRITY-007 | Unmapped field added | `UNMAPPED_FIELD` | `PERMIT_REMAINS_BOUND` | declared-rental-quote |

Vectors 001–005 correspond to upstream candidate scenarios from issue #603.
Vectors 006–007 are semantic controls proving binding is not raw-byte equality.

## Secure trace (PASS)

Example: COAZ-INTEGRITY-001 — operation unchanged after permit.

```text
initial_decision = PERMIT
initial_binding  = A
mutation         = NONE
final_binding    = A
observed         = FORWARDED_WITH_EXISTING_PERMIT
sink.forwarded   = true
verdict          = PASS
```

Example: COAZ-INTEGRITY-003 — mapped argument changed, secure PEP refuses.

```text
initial_decision = PERMIT
initial_binding  = A
mutation         = daily_rate 50 → 5000
final_binding    = B (B != A)
observed         = REFUSED_AFTER_BINDING_CHANGE | DENIED_AFTER_REEVALUATION | FORWARDED_AFTER_REEVALUATION
sink.forwarded   = false (or forward only after re-evaluation)
verdict          = PASS
```

Reference artifact:
[`examples/coaz-integrity/secure/result-pass-v1.json`](../examples/coaz-integrity/secure/result-pass-v1.json)

## Vulnerable trace (FAIL)

For mutation vectors 002–005, `--reference-mode vulnerable` proves stale-permit
forwarding:

```text
initial_decision = PERMIT
initial_binding  = A
final_binding    = B (B != A)
sink.forwarded   = true
observed         = FORWARDED_WITH_STALE_PERMIT
verdict          = FAIL
```

Reference artifact:
[`examples/coaz-integrity/vulnerable/result-stale-permit-fail-v1.json`](../examples/coaz-integrity/vulnerable/result-stale-permit-fail-v1.json)

Secure modes **never** produce this trace. Proven in
[`crates/dare-coaz-integrity/tests/e2e_integrity.rs`](../crates/dare-coaz-integrity/tests/e2e_integrity.rs).

## Semantic control traces (006–007)

Both vectors require:

```text
initial_binding == final_binding
verdict = PASS (secure mode)
```

Vector 006 applies JSON reordering only. Vector 007 adds a field that does not
participate in the declared mapping projection.

## Result and evidence schemas

Each run emits a versioned `VectorResult` (schema major `1`):

- [`schemas/vectors/coaz-integrity/v1/result.schema.json`](../schemas/vectors/coaz-integrity/v1/result.schema.json)

When `--evidence-dir` is set, the CLI also writes Cycle 001 `SecurityEvidence`
with a `dare.coaz.integrity` extension referencing the result artifact:

- Evidence schema: [`schemas/evidence/v1/evidence.schema.json`](../schemas/evidence/v1/evidence.schema.json)
- Examples: [`examples/coaz-integrity/evidence/`](../examples/coaz-integrity/evidence/)

## Offline validation

Vector and result contracts are validated offline in the workspace test suite:

- `crates/dare-coaz-integrity/tests/vector_result_contract.rs`
- `crates/dare-coaz-integrity/tests/vectors.rs`
- `crates/dare-coaz-integrity/tests/standards_snapshot.rs`

Do not fetch JSON Schema `$id` URLs from the network.
