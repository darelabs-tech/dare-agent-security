# task-020 — Implement tool/skill/plugin/MCP supply-chain component projections without Cycle 014 duplication

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-46

## Evidence

`src/projection.rs`.

**AC-46 — agentic surfaces participate in supply-chain provenance.** A tool, a skill plugin, an MCP server and a guardrail arrive in a deployment the same way a package does: somebody published them, somebody pulled them in, and what is running may not be what was approved. `AGENTIC_SURFACE_CLASSES` names those four, and they are ordinary `Component`s — the same identity, digest, provenance and attestation machinery covers them. No parallel model, no second set of rules.

`an_mcp_server_carries_the_same_supply_chain_questions_as_a_package` asserts an MCP server projects with a digest, an origin claim and a comparable capability set.

**No Cycle 014 duplication, enforced structurally.** Cycle 014 owns whether a tool may be *invoked* — by whom, with which arguments, under which policy. This cycle asks where the tool came from and whether it is the artifact that was approved.

A tool can be perfectly authorized and be the wrong artifact; a tool can be the right artifact and be invoked by someone who should not. Two questions, two engines, and an answer to one is not an answer to the other.

`the_projection_cannot_record_a_cycle_014_authorization_decision` asserts `AgenticProjection` serializes no `authorized`, `invocation`, `permitted`, `allowed` or `scope` field, and that `tool_authorized`, `invocation_allowed` and `granted_scopes` fail to decode.

**`EXTERNAL_AGENT` is deliberately not an agentic surface.** `an_external_agent_is_not_an_agentic_surface_of_this_deployment`. It is inventoried (task-021), but it is not a component this deployment supplies, and assessing it as one would have the engine judging the provenance of artifacts nobody here builds or installs.

**A package does not project.** `the_four_agentic_surface_classes_project_and_others_do_not`. A package is a supply-chain component and is assessed as one, but it is not a surface an agent acts through — returning a projection for everything would make the distinction meaningless.
