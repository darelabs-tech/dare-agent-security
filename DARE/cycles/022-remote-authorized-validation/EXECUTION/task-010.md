# task-010 — Add the seven `schemas/remote-validation/v1` JSON schemas

**Status:** DONE  
**Complexity:** MED

## Files

The first four were added with task-010's initial commit, and the other three with the
tasks that defined their documents.

| Schema | Added with |
|---|---|
| `authorization.schema.json`, `plan.schema.json` | task-010 |
| `conversation-request.schema.json`, `conversation-response.schema.json` | task-010; the response was extended by task-027 with optional `goal_id`, `emitted_fields` and `policy_decisions` |
| `capture.schema.json` | task-019 |
| `audit.schema.json` | task-020 |
| `result.schema.json` | task-033 |

All seven are embedded through `include_str!` in `src/schema.rs`, and
`DocumentKind::ALL` has 7 entries. Every schema uses `additionalProperties: false`. The
closed method enum (with `MCP_INITIALIZED`, task-025) is identical in authorization,
plan, capture and audit.

## Tests

- The existing `every_schema_compiles_and_rejects_unknown_fields` covers all 7.
- `tests/runner.rs::a_live_run_and_its_replay_are_byte_identical_and_the_artifacts_are_clean` validates a real live result, capture and audit record against their schemas.

## Ralph Loop

- `cargo test -p dare-remote-validation`: 179 passed
