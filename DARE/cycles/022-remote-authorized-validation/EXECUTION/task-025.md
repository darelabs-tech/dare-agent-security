# task-025 — Implement the MCP protocol client (JSON-RPC, single-response SSE reader, pagination, metadata GETs)

**Status:** DONE (with two recorded deviations)  
**Complexity:** HIGH

## Result (`protocol/mcp.rs`)

`McpClient` provides `initialize`, `list` (tools, resources, prompts, following
`nextCursor` for at most 5 pages, each page a counted request), `read_resource`,
`get_prompt` and `metadata`.

`read_resource` and `get_prompt` accept only a URI or name listed earlier in the same
run. Anything else is refused before the gateway, with no request sent.

`parse_response` finds the JSON-RPC response by `id` in either an
`application/json` body or a `text/event-stream` body (multi-line `data:`,
notifications skipped).

`metadata` GETs expect a possible authentication challenge (`challenge_expected`).

## Deviations (recorded in REGRESSION.md; neither crosses a frozen boundary)

1. **`MCP_INITIALIZED` was added to the closed method enum and all four schemas.** The
   streamable HTTP transport requires `notifications/initialized` after `initialize`.
   It carries no data and has no side effect.
2. **The gateway echoes `Mcp-Session-Id`.** This is the only response value ever sent
   back, and only when it is 1–128 visible ASCII characters. Servers that assign a
   session reject later requests without it.

## Not implemented here

`MCP_AUTH_SERVER_METADATA_GET` on an origin other than the planned one: a plan has
exactly one origin, so an authorization server on another origin is recorded from the
protected-resource metadata but never fetched (Blueprint §5.4).

## Tests

- **Unit:**
  - `a_json_response_is_found_by_id`
  - `an_event_stream_response_is_found_among_events`
  - `metadata_must_be_an_object`
- **Lab:**
  - `every_mcp_method_round_trips_in_json_and_event_stream_form`: all 9 MCP methods, both body forms. The session id is echoed on every request after `initialize` and on none before it, and `MCP-Protocol-Version` is always sent.
  - `a_resource_or_prompt_the_server_never_listed_is_not_requested`
  - `a_method_outside_the_plan_is_refused_by_the_gateway_not_the_client`

The session-echo test caught a defect during development: the header was read but not
re-sent. It was fixed before commit.

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation`: 142 passed (114 unit + 28 integration)
- No dependency change
