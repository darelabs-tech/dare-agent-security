# task-039 — Scope/registration/credential/identity corpus

**Status:** DONE - REVIEW PASS

Build generated paired fixtures for scope step-up, client-registration trust, credential separation and self-reported identity metadata boundaries, including composition with Cycles 003 and 015 where required.

## Evidence

Labs 020–033.

| pair | control | vulnerable | mutation |
| --- | --- | --- | --- |
| scope step-up | 020 | 021 | a retry silently discards privilege the request already required |
| registration trust | 023, 024 | 025 | a client identifier is accepted because an untrusted document asserts it |
| credential separation | 026, 028 | 027 | the credential presented to the MCP server is reused against an upstream service |
| self-reported identity | 029 | 030 | protocol self-description is treated as an authenticated principal |
| final operation | 031, 032 | 033 | the operation changes after the permit and the permit is reused anyway |

Two surfaces carry a second control because the compliant path has more than one legitimate shape. Lab 024 establishes a client from a client metadata document rather than pre-registration; lab 028 obtains the upstream credential through a recorded, authorized exchange rather than by forwarding. Without them the invariant would be satisfiable only by the narrowest legitimate flow, which is a false positive waiting to happen.

Lab 022 asks for a step-up retry past the approved ceiling. It is a scenario the schema must refuse, so it never becomes a corpus vector — `gen_mcp_auth_corpus.py` skips it explicitly, because a vector the loader cannot admit would make the corpus unloadable.

**Composition, not duplication.** Labs 031–033 delegate to Cycle 003's `compute_authorization_binding` and `changed_operation_fields` through `src/compat.rs` rather than re-deciding authorization-to-execution integrity. Lab 030 uses Cycle 015's `PrincipalKind`, re-exported and never redefined.
