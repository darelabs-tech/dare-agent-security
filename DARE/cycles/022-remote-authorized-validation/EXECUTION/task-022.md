# task-022 — Implement `EgressGateway::new` and `send` steps 1–10

**Status:** DONE  
**Complexity:** HIGH

## Result (`gateway.rs`)

**Client.** The single `reqwest::Client` is built with:
- `redirect(Policy::none())`, `https_only(true)`, `no_proxy()`, `pool_max_idle_per_host(0)`;
- connect timeout 5 s, total 15 s;
- the `PinnedResolver`, and no default headers;
- TLS trust from the platform verifier, or only the lab root (`TrustRoots::LabRoot`, test builds only).

**`OutboundRequest`** has no URL, path or header field. The gateway derives all three
from the method and the verified authorization.

**`send`: steps 1–5, before any byte leaves.**
1. The operator-stop flag and the kill switch.
2. The window (`WindowExpired`).
3. The method is in the plan.
4. The path comes from the method, and the body is within the limit.
5. The Cycle 009 budget, then the spacing rate limiter.

**`send`: steps 6–10.**
- Only the fixed headers are sent: `Accept`, `User-Agent`, `Content-Type`, the credential and `MCP-Protocol-Version`.
- The body is read in chunks against the limit, and an oversize partial body is dropped.
- The peer address is re-checked against the pin (IP literal or resolved set).
- The body and `WWW-Authenticate` are scrubbed and neutralized.
- The exchange is captured and audited.
- The kill triggers run:
  - credential echo → `SecretDetected`;
  - unexpected 401/403 → `UnexpectedIdentity`;
  - `429`/`5xx` → `TargetInstability`;
  - `3xx` → `UnexpectedTarget`.

**Errors.**
- Transport errors become capture entries with a `TransportOutcome`.
- A resolver refusal is not a capture entry (nothing was exchanged). It is an audit event and `Err(Egress(...))`.

## Tests (`tests/gateway.rs`, `tests/no_proxy.rs`, `tests/window.rs`)

**What is sent and how:**
- `a_request_reaches_the_authorized_path_with_only_the_fixed_headers`
- `a_method_outside_the_plan_is_refused_before_anything_is_sent`
- `an_oversize_request_is_refused_before_anything_is_sent`
- `the_request_after_the_budget_is_never_sent`
- `requests_are_spaced_by_the_rate_limit` (≥ 495 ms, as measured by the lab)

**Responses and kill triggers:**
- `an_oversize_response_is_dropped_and_never_captured`
- `an_echoed_credential_is_scrubbed_and_kills_the_run`: the token appears nowhere in the capture or audit, and the next request never leaves
- `a_redirect_is_not_followed_and_kills_the_run`: the redirect target gets 0 hits
- `instability_stops_the_run_on_first_fail`
- `an_unexpected_401_kills_on_identity`
- `the_operator_stop_flag_blocks_the_next_send`
- `control_and_bidi_characters_in_a_response_are_neutralized`

**Transport and resolution:**
- `a_certificate_for_another_name_is_a_tls_error`
- `a_closed_port_is_a_connection_error`
- `a_resolution_to_a_forbidden_address_sends_nothing`
- `a_pinned_hostname_is_used_for_every_request`

**Environment and window:**
- `proxy_variables_pointing_at_a_dead_port_do_not_affect_the_gateway`
- `no_request_leaves_after_the_window_closes`

## Not directly tested

The peer-address re-check (the TCP peer is not in the pin) cannot be staged on loopback,
because every peer there is `127.0.0.1`. The check is exercised on every successful
request, which passes only because the peer matches. REGRESSION.md records this as a
coverage limit.

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation`: 103 unit + 16 gateway + 4 lab harness + 1 no-proxy + 1 window = 125 passed
- `cargo audit`: exit 0 after adding the dev-dependencies
