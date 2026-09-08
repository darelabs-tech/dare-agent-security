# task-022 — Implement capability projection and reuse existing capability-drift property

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-04, AC-41

## Evidence

`src/capability.rs`.

**AC-04 — the existing property is reused, not duplicated.** This module supplies evidence to `AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT`, which Cycle 012 created. It does not create an `AGENT.SUPPLY.CAPABILITY_DRIFT` or any other parallel drift property. Two properties both meaning "capabilities changed" would eventually disagree about what drift is, and a report would have to explain to its reader which one they were looking at.

`crates/dare-coverage/tests/supply_chain_properties.rs` asserts the registry holds exactly the two inherited properties plus the eight additive ones, and that no `AGENT.SUPPLY.*` namespace exists.

**AC-41 — PASS, FAIL and INCONCLUSIVE all have tests.**

- PASS: `an_unchanged_capability_set_has_not_drifted`.
- FAIL: `an_introduced_capability_is_drift_and_is_named` — and it is named. "This tool drifted" is not actionable; "this tool gained `write-file`" is.
- INCONCLUSIVE: `one_side_alone_is_not_comparable` and `no_projection_at_all_is_also_not_comparable`. `drifted()` returns `Option<bool>`, and a one-sided projection returns `None` rather than `Some(false)`.

**Drift is asymmetric.** A capability *introduced* since approval is a finding. One *withdrawn* is recorded and is not — a component doing less than it was approved to do has not crossed a boundary, and reporting it as drift would train an operator to skim past drift findings. `a_withdrawn_capability_is_recorded_and_is_not_drift`.

**The manifest wins over the component own approved set.** `the_manifest_wins_over_the_components_own_approved_set`. A component describing its own approved capabilities would be approving itself; the fallback to the component projection exists only for evidence bundles that carry one with no manifest beside it.

**Every capability-bearing class is assessed.** `drift_is_reported_for_any_component_class_that_carries_capabilities` covers `TOOL`, `MCP_SERVER`, `SKILL_PLUGIN` and `GUARDRAIL`. An engine that only looked at `TOOL` would miss the surfaces most likely to gain a capability quietly.

**The boundary with Cycle 014 is asserted.** `the_assessment_says_nothing_about_runtime_authorization`. A component may drift and still be correctly authorized, and may be correctly authorized and still have drifted.
