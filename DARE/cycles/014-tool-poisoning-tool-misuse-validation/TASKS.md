# Cycle 014 — Tasks

**Status:** IN PROGRESS
**Approval:** APPROVED — see `APPROVAL.md`

- [x] task-001 — Reconcile current main baseline and freeze compatibility contracts
- [x] task-002 — Record Cycle 013 lessons/residual risks and ASI02 standards provenance
- [x] task-003 — Freeze/add Tool Security AGENT.* properties and applicability predicates
- [x] task-004 — Define ToolSecurityScenario schema
- [x] task-005 — Define ToolSurfaceSnapshot and ApprovedToolPolicy schemas
- [x] task-006 — Define tool-security corpus-entry and replay trace schemas
- [x] task-007 — Define poisoning/misuse/source/trust closed enums
- [x] task-008 — Define normalized Tool Observation event model
- [x] task-009 — Define invariant-specific positive PASS coverage contracts
- [x] task-010 — Implement deterministic Tool Security invariant evaluator registry
- [x] task-011 — Implement canonical scenario/corpus/objective/policy/tool-surface digest binding
- [x] task-012 — Implement bounded trials, tool-request counts and chain-depth enforcement
- [x] task-013 — Implement replay adapter
- [x] task-014 — Implement simulated adapter
- [x] task-015 — Integrate local-synthetic harness with Cycle 009 controls
- [x] task-016 — Build Tool Poisoning corpus with paired secure/vulnerable fixtures
- [x] task-017 — Build Tool Misuse corpus with paired secure/vulnerable fixtures
- [x] task-018 — Add benign controls and false-positive regressions
- [x] task-019 — Add hostile parser/schema/trace fixtures and executable-field refusal
- [x] task-020 — Implement deterministic selection, argument, output-trust, chain and policy checks
- [x] task-021 — Implement independent multi-violation capture and secret/redaction hygiene
- [ ] task-022 — Implement ToolSecurityResult and Cycle 001 evidence bridge
- [ ] task-023 — Add `tool-security-baseline-2026` profile and coverage integration
- [ ] task-024 — Add `validate tool-security` CLI integration
- [ ] task-025 — Add product/report integration with bounded-claim wording
- [ ] task-026 — Add confidential/offline/no-remote-tool regressions
- [ ] task-027 — Add dedicated Cycle 014 CI security gate and execute workflow job locally
- [ ] task-028 — Document operator safe-use semantics and limitations
- [ ] task-029 — Document contributor corpus/property/evaluator extension process
- [ ] task-030 — Run complete workspace, Cycle 013, Agentic and MCP compatibility regression
- [ ] task-031 — Final DARE proof and Cycle 014 completion gate

Execution order and dependencies are authoritative in `dare-dag.exec.yaml`. Each task must read its `EXECUTION/task-NNN.md` before implementation.
