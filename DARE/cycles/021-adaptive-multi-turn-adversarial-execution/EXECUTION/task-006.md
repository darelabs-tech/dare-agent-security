# task-006 — Add JSON schemas (scenario, strategy graph, transcript, result)

**Status:** DONE  
**Complexity:** MED

## Files changed

- `schemas/multi-turn-security/v1/scenario.schema.json`
- `schemas/multi-turn-security/v1/strategy-graph.schema.json`
- `schemas/multi-turn-security/v1/transcript.schema.json`
- `schemas/multi-turn-security/v1/result.schema.json`
- `crates/dare-multi-turn-security/src/schema.rs` (embedded copies + validation)

## Result

The four draft 2020-12 schemas are self-contained: every `$ref` stays inside the file's
own `$defs`. Each uses `additionalProperties: false` and closed enums that mirror
Blueprint §4.3. The id pattern is `^[a-z0-9][a-z0-9._-]{0,63}$` and digests are
`^sha256:[0-9a-f]{64}$`. Enforcement highlights:
- the graph schema's edge enum excludes `UNCLASSIFIABLE`;
- the result schema pins `state_changes` and `egress_bytes` to `0` and
  `redaction_state` to `REDACTED`.

## Deviation recorded

Blueprint §4.5 names the canary value `CanarySpec.token`. `token` is a forbidden
credential field name in the hostile sweep this repository applies to every fixture
(Cycles 013–020), so the field is named **`marker`** (pattern `^CANARY-[A-Z0-9]{12}$`).
Semantics are unchanged.

## Tests (`schema::tests`)

- `every_embedded_schema_compiles_and_self_describes`
- `the_embedded_copies_equal_the_files_on_disk`
- `no_schema_reaches_outside_its_own_file`
- `the_graph_schema_has_no_generation_field_and_no_unclassifiable_edge`
- `an_unknown_field_is_rejected_and_the_value_is_not_echoed`
- `versions_other_than_one_are_refused`

## Container (AD-10)

The embedded paths are `../../../schemas/multi-turn-security/v1/*`. `schemas/` is copied by
the root `Dockerfile`.

## Ralph Loop

- Build/Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 266 suites, 3 796 passed, 0 failed (+15 over task-005)
- Audit: `cargo audit` exit 0 (305 crates). The first attempt hit a transient crates.io `503` on yank checks; the retry was clean. `jsonschema` was added from the workspace (already audited, no new crate in the lockfile).
