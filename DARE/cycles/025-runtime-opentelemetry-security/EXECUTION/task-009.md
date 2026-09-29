# task-009 — Implement the semconv classifier

**Status:** DONE  
**Complexity:** LOW

- **`src/semconv.rs`** loads `standards/runtime-telemetry/2026/semconv-mapping.json`
  (embedded with `include_str!`; `standards/` is copied by the Dockerfile).
  - Every struct is `deny_unknown_fields`, and the mapping digest is canonical.
  - It exposes the releases and schema URLs, the keys, the content keys, the
    principal/tenant allow-lists, the required keys per kind, and `known_keys`.
- **`classify(span)`** follows the mapping only:
  1. `gen_ai.operation.name` → AGENT_INVOKE, MODEL_CALL, TOOL_EXEC, RETRIEVAL or MEMORY,
     by the exact operation-name lists;
  2. otherwise `mcp.method.name` present → MCP_CALL;
  3. otherwise a CLIENT span with `http.request.method` → HTTP_CLIENT;
  4. anything else is UNRECOGNIZED.
- **`src/canonical.rs`** (sorted-key compact JSON digest) is added for this and later
  digests.

## Tests

- `the_embedded_mapping_loads_with_its_pins`
- `every_kind_is_recognized_from_the_mapping_alone`
- `anything_else_is_unrecognized_never_guessed`: `invoke_workflow`, a wrong-case
  operation, an HTTP method on a SERVER span, an unknown key, an empty CLIENT span.
- `a_malformed_mapping_is_an_internal_error`
- `key_order_and_whitespace_do_not_change_the_digest`

Ralph Loop green: 31 crate tests.
