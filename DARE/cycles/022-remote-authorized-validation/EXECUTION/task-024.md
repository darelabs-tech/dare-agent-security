# task-024 — Implement the A2A protocol client

**Status:** DONE (with a recorded refinement)  
**Complexity:** MED

## Result (`protocol/a2a.rs`)

- **Requests:** `fetch_card`, `send_message` and `get_task` go through the gateway.
- **Pure parsers:** `parse_card`, `parse_reply`, `declared_version`.
- **Replies:** a JSON-RPC error is an observation (`error_code`), not a transport failure. A reply with the wrong `id` is a protocol violation.
- **Reply shapes:** a Message or a Task (also wrapped as `{task}`/`{message}`). Text parts, part kinds and sizes, the task id, the context and the state are extracted.

## Refinement (recorded in REGRESSION.md)

BLUEPRINT §5.4 names `message/send` and `tasks/get`, which are 0.3-era names, while the
pinned version is A2A 1.0.0. Upstream re-verification was not possible in this session,
so `rpc_names` selects `message/send`/`tasks/get` when the card declares `0.*`, and
`SendMessage`/`GetTask` otherwise.

The card's `url` is **never** used as a destination. Every request goes to
`origin + endpoints.a2a_rpc` (`the_card_url_never_redirects_the_client`).

## Tests

- **Unit:**
  - `method_names_follow_the_declared_version`
  - `a_card_needs_a_name_and_must_be_an_object`
  - `a_message_reply_and_a_task_reply_both_parse`
  - `a_jsonrpc_error_is_an_observation_and_a_wrong_id_is_not`
  - `request_bodies_have_the_documented_shape`
- **Lab:**
  - `a2a_card_message_and_task_round_trip_with_version_selected_names` (0.3.0 and 1.0.0)
  - `the_card_url_never_redirects_the_client`

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation`: 142 passed (114 unit + 28 integration)
- No dependency change
