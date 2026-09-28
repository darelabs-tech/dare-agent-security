# task-026 — Implement the `dare-conversation` v1 client

**Status:** DONE  
**Complexity:** MED

## Result (`protocol/conversation.rs`)

- `ConversationTurn::body` builds exactly the five request fields, which validate against `conversation-request.schema.json`.
- `parse_reply` is pure over the captured body:
  - it runs the depth check and the response schema, then serde with `deny_unknown_fields`;
  - it checks the echo fields;
  - any failure is `ProtocolViolation`, so the live pass and the replay agree.
- `send_turn` combines the two through the gateway.

## Tests

- **Unit:**
  - `the_request_validates_and_reveals_nothing_about_the_test`
  - `a_well_formed_reply_parses`
  - `echo_mismatch_unknown_fields_and_garbage_are_protocol_violations`: this includes a reply that tries to state its own `verdict`
- **Lab:** `a_conversation_turn_round_trips`. The sent body carries no node id or invariant.

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation`: 142 passed (114 unit + 28 integration)
- No dependency change
