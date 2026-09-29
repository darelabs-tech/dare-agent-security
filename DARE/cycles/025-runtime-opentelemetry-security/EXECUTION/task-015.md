# task-015 — Implement evaluators B-5 (egress) and B-6 (retry bound, BQ-4)

**Status:** DONE  
**Complexity:** MED

- **B-5 (`egress.rs`).**
  - Scope: HTTP client spans inside an agent's subtree. A client span with no agent above
    it is not the agent's egress.
  - The host comes from `server.address`, or else from `url.full` through `url_host`
    (drops userinfo, port, path, query and fragment; unwraps IPv6).
  - The host is matched with `host_allowed` (exact, or strict `*.` subdomain). A miss →
    `egress_not_allowed`.
  - An unknown agent → `unknown_agent`. A missing host → gap.
- **B-6 (`retry.rs`), BQ-4 (a).**
  - A group is the siblings under one parent with the same kind and target (tool name;
    HTTP method + host; MCP method + tool), in trace order.
  - Retries = attempts that follow a failed attempt (status code 2).
  - More than the agent's `max_retries` → `retries_above_bound`.
  - `http.request.resend_count` above the bound → `resend_count_above_bound` (R-1).
  - Agents without a bound are not judged.

## Tests

- **`url_host`:** userinfo, port, path, IPv6, fragment, non-URL and empty-host cases.
- **B-5:** allowed hosts (exact and wildcard) pass; another host fails without echoing
  it; a `url.full` host fails with the `url.full` key; a hostless client is INCONCLUSIVE;
  a client outside any agent → NOT_EXERCISED.
- **B-6:** 1 retry within bound 1 passes; 2 retries fail; repeated successes and
  different targets are not retries; a resend count of 3 fails; an unsampled trace is
  INCONCLUSIVE.

Ralph Loop green.
