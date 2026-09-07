# task-045 — CLI and bounded reports

**Status:** DONE - REVIEW PASS

Add `dare-agent-security validate mcp-auth-security` with local scenario/mode/trace/output controls only. Do not expose provider, endpoint, credential, IdP, token, JWKS or registration connection flags. Emit bounded product/report artifacts.

## Evidence

`crates/dare-agent-security-cli/src/mcp_auth_security.rs`, wired into `args.rs`, `lib.rs` and `main.rs`. 15 tests in the module, all passing.

**The flag surface is exactly the six approved ones** — `--scenario`, `--mode`, `--trace`, `--trials`, `--output-dir`, `--json`. Two tests hold that from both directions: `the_prohibited_endpoint_and_credential_flags_do_not_exist` checks all fourteen flags the approval forbids by name plus nine more that would each imply their own client, and `the_command_exposes_exactly_the_six_approved_flags` enumerates the command's real argument list, which catches a flag added later that nobody thought to forbid.

Unlike Cycle 017 there is no `--corpus` override, because the approved list does not include one. The corpus root is fixed in code rather than reachable from the command line.

**Run end to end, not just parsed.** Three real invocations:

| scenario | mode | exit | verdict |
| --- | --- | --- | --- |
| MCP-AUTH-LAB-001 | simulated | 0 | PASS |
| MCP-AUTH-LAB-027 | simulated | 2 | FAIL |
| MCP-AUTH-LAB-035 | simulated | 2 | INCONCLUSIVE |

All four artifacts are written: `mcp-auth-security-result.json`, `mcp-auth-security-trials.json`, `mcp-auth-security-evidence.json`, `summary.md`.

**Replay was implemented but had never been exercised end to end** — the crate had no trace fixture, so `--mode replay --trace` was reachable only through unit tests that built traces in memory. Claiming the flag worked on that basis would have been a claim without evidence, so this task added the fixtures:

- `scripts/k18/gen_mcp_auth_traces.py` derives six traces from the lab scenarios rather than hand-writing them, so a trace cannot silently disagree with the scenario it claims to replay. Only the observed *requests* are copied: a trace carries no verdict, no expectation and no invariant.
- `crates/dare-mcp-auth-security/tests/replay_traces.rs` (7 tests) checks that each bound trace replays to the same verdict the staged run reaches, and that `trace-unbound-operation.json` — which keeps the approved `scenario_id` and widens the operation, the exact shape of the Cycle 017 defect — is refused before any evaluator sees it. `run_scenario` re-checks the binding itself, so a caller that forgot `assert_matches` still cannot get a verdict out of an unbound trace.

Confirmed at the command boundary too:

```
--mode replay --trace trace-lab-001.json           exit 0, Mode REPLAY, Verdict PASS
--mode replay --trace trace-unbound-operation.json exit 3, no artifacts written
  binding mismatch: an observation changes the operation semantics of request `req-1`
```

**Two write gates.** `assert_bytes_are_secret_safe` refuses to write any artifact carrying a canary or credential marker, checked on shape so an honest sentence about bearer credentials stays writable. `assert_summary_is_bounded` refuses sixteen unbounded phrasings, including the conformance claims — "spec compliant", "authzen compliant", "oauth 2.1 compliant" — that would turn a bounded run into a standards assertion.

The summary reports all six surfaces and marks the five a given scenario did not exercise as NOT TESTED, because "not tested" and "passed" are different answers. It also carries the counts that make the offline boundary checkable at a glance: authorization-code exchanges, metadata documents retrieved, tokens verified against a key set, clients registered, protected-resource calls, state changes and external egress bytes, all zero.

`cargo test -p dare-agent-security`: 282 passed, 0 failed. clippy clean.
