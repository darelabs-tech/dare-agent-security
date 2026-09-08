# task-049 — Run Cycle 012–018, MCP baseline and coverage compatibility regressions

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-78, AC-79

## Evidence

Recorded in `REGRESSION.md` §3 with exact counts.

| Cycle | Crate | Passed | Failed |
|---|---|---|---|
| 012 | `dare-coverage` | 326 | 0 |
| 013 | `dare-prompt-injection` | 271 | 0 |
| 014 | `dare-tool-security` | 276 | 0 |
| 015 | `dare-identity-security` | 323 | 0 |
| 016 | `dare-memory-security` | 265 | 0 |
| 017 | `dare-rag-security` | 283 | 0 |
| 018 | `dare-mcp-auth-security` | 348 | 0 |

**AC-79 — the compatibility risk is not that these break loudly.** It is that a denominator or a property definition moves and every figure already filed against it silently means something else. That is pinned separately, by count, in `no_earlier_profile_moved` and by `the_mcp_registry_is_untouched_by_a_supply_chain_property`.

The regression block also runs inside the `supply-chain-security-2026` CI job, so a future change to Cycle 019 that breaks an earlier engine fails this cycle's own gate rather than someone else's.

## One flaky test, recorded rather than hidden

`stdio_current_protocol_trace_is_subset_of_allowlist` (Cycle 002 discovery, `crates/dare-agent-security-cli/tests/e2e_matrix.rs`) failed once under full-workspace parallelism and passed in isolation and on the final full run. It is temp-trace-path contention, unrelated to Cycle 019, and is recorded in `REGRESSION.md` §9 rather than left unmentioned.
