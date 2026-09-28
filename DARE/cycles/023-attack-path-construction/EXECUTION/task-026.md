# task-026 — Implement the prompt-injection projector (§6.8)

**Status:** DONE  
**Complexity:** LOW

## Change

`project/prompt_injection.rs`. The channel DATA node is named from `source_kind`. It is an `UNTRUSTED_INPUT` entry for a DIRECT injection and an `EXTERNAL_CONTENT` entry for an INDIRECT one. Every trial gives channel `TRANSFERS_TO` SUT, guarded by the result's property. A `StructuredActionRequest` gives SUT `CAN_INVOKE` tool.

## Tests (`crates/dare-attack-path/tests/projection_tables.rs`)

`prompt_injection_rows`. Every projected edge is also checked by `all_have_evidence`:
- it carries evidence ids;
- an OBSERVED edge cites evidence records;
- a STATICALLY_PROVEN edge cites `input:<engine>:` ids only;
- it has a locator and an original kind.

The inputs are real engine output (the fixture bundles of tasks 014–016).

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-path` (60 tests).
