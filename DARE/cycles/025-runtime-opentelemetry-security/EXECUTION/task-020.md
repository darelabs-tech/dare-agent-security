# task-020 — Add the `runtime-telemetry-baseline-2026` profile

**Status:** DONE  
**Complexity:** LOW

## Profile (`profiles/runtime-telemetry-baseline-2026.json`, sha256 `dc0bb1b0ddfc4fc5…`)

The profile has nine properties, in rule order:

| Property | Rule | Level |
|---|---|---|
| AGENT.TOOL.AUTHORIZATION_BOUNDARY | B-1 | CONDITIONAL |
| AGENT.HUMAN_APPROVAL.INTENT_BINDING | B-2 | CONDITIONAL |
| AGENT.IDENTITY.PRINCIPAL_BINDING | B-3 | CONDITIONAL |
| AGENT.RAG.TENANT_DOCUMENT_ISOLATION | B-4R | CONDITIONAL |
| AGENT.MEMORY.TENANT_BOUNDARY | B-4M | CONDITIONAL |
| AGENT.CODE_EXECUTION.EGRESS_BOUNDARY | B-5 | CONDITIONAL |
| AGENT.FAILURE.RETRY_AMPLIFICATION | B-6 | REQUIRED |
| AGENT.TELEMETRY.CONFIDENTIALITY | T-1 | REQUIRED |
| AGENT.TELEMETRY.COMPLETENESS | T-2 | REQUIRED |

**Level rule:** a property is REQUIRED exactly when its registry predicates are only
`agent_present` and `runtime_trace_present`, that is, when every traced agent has the
surface. A test enforces this rule. The other properties are CONDITIONAL, because
tools, approvals, principals, retrieval, memory or egress may be absent from the traced
system.

## Registration (`dare-coverage/src/profile.rs`)

The profile is registered in the four places:
1. the const `RUNTIME_TELEMETRY_PROFILE_JSON`;
2. the function `runtime_telemetry_profile()`, with a doc comment;
3. the `resolve_profile` arm;
4. the re-exports in `lib.rs`.

## Engine

`coverage::baseline_report(result)` builds the Cycle 006 report over this profile.

## Tests

`dare-coverage/tests/runtime_telemetry_profile.rs` has 6 tests:
- `the_profile_matches_the_approval_exactly`, which includes resolution by name;
- `every_selected_property_is_registered`;
- `required_means_every_traced_agent_has_the_surface`;
- `a_traced_agent_makes_every_required_property_applicable`;
- `no_earlier_profile_denominator_moved`, which checks all 11 earlier profiles against
  literals and the new profile's 9;
- `no_earlier_profile_selects_a_cycle_025_property`.

`dare-runtime-telemetry/tests/evidence.rs` adds
`the_baseline_report_covers_the_nine_properties_of_the_profile`.

No earlier test is edited.

## Ralph Loop

| Step | Result |
|---|---|
| Build | ok |
| Test | `dare-coverage`: all suites ok. `dare-runtime-telemetry --test evidence`: 10/10. BQ-1 pins: 8/8 and 4/4. The 11 earlier profiles are byte-identical; the new profile is the only new file in `profiles/` |
| Lint | fmt and clippy `-D warnings`: clean |
| Audit | No dependency change |
