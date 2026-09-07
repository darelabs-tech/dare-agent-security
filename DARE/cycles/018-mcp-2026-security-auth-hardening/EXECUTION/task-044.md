# task-044 — Profile and coverage integration

**Status:** DONE - REVIEW PASS

Add `mcp-auth-hardening-2026` profile and registry/coverage integration without changing existing profiles or denominator semantics. Keep standards provenance/status explicit.

## Evidence

`profiles/mcp-auth-hardening-2026.json`, registered in `crates/dare-coverage/src/profile.rs` as `mcp_auth_hardening_profile()` and resolvable by name. `crates/dare-coverage/tests/mcp_auth_profile.rs` — 16 tests, all passing.

It selects from the **v1** MCP registry rather than the v2 Agentic one, which is where the ten properties live. That placement is what keeps the Agentic risk-family count at ten without an exclusion rule: these are MCP protocol and OAuth surfaces, not agent behaviours, and there is no honest eleventh family to add. `the_profile_selects_from_v1_and_not_from_the_agentic_registry` and `the_agentic_risk_families_still_number_exactly_ten` pin both halves.

**All ten are REQUIRED, and this is the one place the cycle deviates from the shape of every earlier profile.** The first draft marked PKCE, scope step-up and client-registration trust CONDITIONAL, on the reasoning the earlier cycles use — a target may honestly have nothing to answer for there. Building the coverage test showed that reasoning does not survive contact with AC-08.

Only REQUIRED properties feed the required-coverage ratio (`math.rs::required_eligible_count`). Seven of these ten are gated on an *auth control/evidence* predicate, and when one of those is absent applicability reports NOT_TESTED — a gap — precisely so a missing control cannot be relabelled away. Marking such a property CONDITIONAL would leave the gap printed in the report and counting toward nothing: the same evasion AC-08 forbids, reached through a different door.

The honest "nothing to answer for" case is handled one layer down and more precisely. The remaining gating predicates are *target shape* — the protocol revision, the HTTP transport, whether an authorization flow exists at all — and when one of those is false the property is NOT_APPLICABLE and leaves the denominator entirely. `a_target_on_a_legacy_revision_reports_every_auth_property_not_applicable` shows that path; `every_auth_control_predicate_reports_a_gap_when_its_evidence_is_absent` shows the other, across all seven rather than one sampled property.

**Nothing earlier moved.** `no_earlier_profile_changed` pins all seven prior profiles by id and property count; `the_earlier_v1_profile_keeps_every_requirement_level_it_had` pins `mcp-security-baseline` requirement level by requirement level, because a count alone would not catch OPTIONAL becoming REQUIRED — which changes what a gap means without moving a denominator. `the_auth_profile_selects_no_property_an_earlier_profile_selects` rules out overlap, which is how a coverage number inflates without anyone editing one.

Standards provenance is unchanged and stays explicit: the mappings in `standards/mcp-auth-security/2026/provenance.json` remain INFORMATIVE or OPEN_PROPOSAL, and the profile asserts no conformance.

`cargo test -p dare-coverage`: 280 passed, 0 failed.
