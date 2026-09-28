# task-036 — Add the egress, rate/budget, credential-hygiene, authorization-refusal and replay-equivalence suites

**Status:** DONE  
**Complexity:** MED

## Files

| File | What it proves |
|---|---|
| `tests/egress.rs` | The §4.4 table through the public `classify`/`permitted`: all four `172.16/12` edges, 17 rows including IPv4-mapped forms. Metadata, link-local and reserved addresses are never permitted in any scope. |
| `tests/no_proxy.rs` (task-022) | `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY` (both cases) pointing at a dead port do not affect the gateway. |
| `tests/rate_and_budget.rs` | At 2 req/s, 5 consecutive lab hits are ≥ 495 ms apart. Request 501 is never admitted under the hard ceiling. `max_duration_s: 1` sends exactly 2 requests, then stops with `BUDGET_EXHAUSTED`. |
| `tests/authorization_refusal.rs` | Each §4.5 rule through the public `verify` (01–16), with no refusal display carrying the token. Window edges: `now == not_before` is allowed, `now == not_after` is refused, and one second before `not_before` is refused. |
| `tests/replay_equivalence.rs` | Changing any of six fields of any entry gives `CaptureTampered(<that entry>)`. A changed audit, a changed origin or a dropped entry is refused. Positive equivalence is asserted for every non-refusal REMOTE-LAB entry (task-035). |
| Credential hygiene | REMOTE-LAB 028–030, `gateway.rs::an_echoed_credential_is_scrubbed_and_kills_the_run`, and the scrubber unit tests. |

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation`: **232 passed, 0 failed**
