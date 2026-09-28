# task-016 — Implement bundle handling for prompt-injection, multi-turn and remote

**Status:** DONE  
**Complexity:** MED

## Change

- **Prompt injection:** result-only. The result's `evidence_ids` must all be in the
  evidence file. `scenario_digest` is recorded in `input_digests` and not re-verified.
- **Multi-turn:** reads the sibling `multi-turn-conversations.json` as
  `Vec<ConversationRun>`. The conversation count must match, and each conversation must
  pass `ConversationState::verify_chain()`, the engine's own chain check. Its `head()`
  must equal `result.conversations[i].final_chain_digest`. The SHA-256 of the
  conversations file is pinned.
- **Remote:**
  - `remote-result.json` must validate against the embedded
    `schemas/remote-validation/v1/result.schema.json`, and nothing from the
    `dare-remote-validation` crate is used;
  - each `runs[i]` becomes a `RemoteRun`, whose `verdict` is the verdict after the
    transport overlay;
  - `engine_result` is decoded as the owning engine's result type, or `None` when it is
    `null`;
  - an optional `inputs/run-<i>/scenario.json` binds an MCP-auth run to its
    `scenario_digest`.

## Tests

- `every_fixture_bundle_binds` covers the `pi`, `mt` and `remote` bundles. `remote` is the
  output of `validate replay-capture` over the Cycle 022 CLI fixture.
- `a_multi_turn_transcript_must_match_its_result`: one character of a turn's
  `chain_digest` is changed, and the result is `DigestMismatch("conversations")`.
- `a_remote_result_must_match_the_022_schema`: an `http://` origin gives
  `InvalidDocument("result")`.

## Ralph Loop

Green: fmt, clippy `-D warnings`, tests.
