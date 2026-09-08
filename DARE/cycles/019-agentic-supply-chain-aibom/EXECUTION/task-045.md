# task-045 — Add `agentic-supply-chain-security-2026` profile and coverage integration

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-70, AC-71, AC-72

## Evidence

`profiles/agentic-supply-chain-security-2026.json`, `crates/dare-coverage/src/profile.rs`, `crates/dare-coverage/tests/supply_chain_profile.rs`.

**AC-70 — additive by construction.** Ten properties: the two Cycle 012 created plus the eight this cycle added. `the_profile_is_exactly_what_the_approval_authorized` checks ids, order and requirement levels against the approval.

**AC-71/AC-72 — nothing earlier moved, and this is the half that would fail quietly.**

A coverage percentage is a fraction whose denominator is a profile's property count. If adding this profile had changed an earlier one, every assessment already filed against that earlier profile would silently mean something different from what it meant when it was produced — and **nothing about the number would look wrong**.

`no_earlier_profile_moved` pins all eight earlier denominators by count (10/10/3/6/6/6/6/10 — they differ because the cycles that produced them selected different numbers of properties, and what matters is that each is the number it was).

`the_agentic_baseline_still_selects_what_it_always_selected` is the sharper one. That baseline **already carries** `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE`, so adding the seven new properties to it would have been the natural way to make them visible — and would have changed a denominator eight cycles of assessments were filed against. The test asserts none of the eight was added there.

`the_mcp_registry_is_untouched_by_a_supply_chain_property` closes the other direction: a supply-chain property in the v1 MCP registry would appear in every MCP assessment's denominator.

**Four REQUIRED, six CONDITIONAL, and the split is deliberate.** `the_split_between_required_and_conditional_is_deliberate`. Identity, integrity, source trust and completeness apply wherever a bill of materials exists at all. The rest apply where their evidence class exists — a system with no model has no model lineage to preserve, and marking lineage REQUIRED would report a finding against every deployment that runs no model.

**Resolution and digest stability.** `the_profile_resolves_by_name_and_by_path` — an operator naming the profile and a CI job pointing at the file must get the same denominator, or one run would report two coverage numbers. `the_profile_digest_is_stable` — the digest is what a report cites to say which denominator produced a number.
