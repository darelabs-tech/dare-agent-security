# task-002 — Record standards status snapshot

**Status:** DONE — REVIEW PASS

Re-verify and freeze the Cycle 018 standards snapshot for MCP `2026-07-28`, referenced OAuth/OIDC metadata requirements, AuthZEN 1.0, COAZ/COAZ-MCP draft status and `openid/authzen#603` open-proposal status. Keep DPoP, workload identity, ID-JAG and token exchange forward-looking unless upstream status changes.

## Evidence

`standards/mcp-auth-security/2026/provenance.json` and
`crates/dare-coverage/src/mcp_auth_security_standards.rs`.

- 11 sources recorded with statuses NORMATIVE / DRAFT / OPEN_PROPOSAL / FUTURE / INTERNAL.
- MCP `2026-07-28` and its authorization specification are NORMATIVE; AuthZEN 1.0 is
  NORMATIVE where an externalized decision is modelled; COAZ and COAZ-MCP stay DRAFT;
  `openid/authzen#603` stays OPEN_PROPOSAL; DPoP / workload identity / ID-JAG / token
  exchange / Enterprise-Managed Authorization are FUTURE and are never PASS requirements.
- `reverification_note` states plainly that no upstream re-verification was performed in
  this environment, so a status is recorded as approved rather than as confirmed-current.
  Nothing claims a status changed.
- Eight pinned source statuses are enforced by test: promoting COAZ, `authzen#603` or the
  roadmap items is refused.
- A property mapping may never claim `NORMATIVE`, `CONFORMS_TO` or `EQUIVALENT` — the
  source carries normative status, the mapping carries attribution.
- Wording checks are anchored on the claim, not the vocabulary, so denying conformance
  stays writable while asserting it does not. A denial in one sentence does not license a
  claim in the next.

`cargo test -p dare-coverage --lib mcp_auth_security_standards` → **19 passed**.

Two defects were found and fixed while writing this suite, both in my own tests: an
inverted assertion that panicked on exactly the `Err` proving the check works, and an
honest denial (`nothing here is MCP compliant`) that the inherited negation detector
refused. The detector was widened to recognise `nothing ` rather than rewording the
manifest around it.
