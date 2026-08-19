# Cycle 002 — Execution Approval

> Cycle: `002-mcp-discovery-baseline`
> Status: **APPROVED FOR EXECUTION**
> Approved: 2026-08-18
> Issue: #3
> Pull request: #6
> Branch: `agent/cycle-002-mcp-discovery-baseline`

## Approval decision

All Cycle 002 planning and execution artifacts are approved for implementation.

Canonical artifacts:

- `DESIGN.md`
- `BLUEPRINT.md`
- `TASKS.md`
- `dare-dag.yaml`
- `dag-graph.mmd`
- `EXECUTION/task-001.md` through `EXECUTION/task-012.md`

The approved implementation scope is passive MCP discovery and the enterprise security baseline described by those artifacts.

## Execution rules

1. Follow `dare-dag.yaml` dependency order.
2. Read the applicable `EXECUTION/task-NNN.md` before modifying code.
3. Preserve the approved Design and Blueprint invariants.
4. Do not redesign the cycle during Execute.
5. If implementation requires a semantic/architectural deviation, stop and return to DARE Review.
6. Mark a task DONE only after its validation gates pass.
7. Keep the existing PR #6 open through implementation; do not create a second Cycle 002 PR.

## Mandatory security invariants

Discovery mode must remain passive by construction:

```text
NO tools/call
NO resources/read
NO prompts/get
NO recursive target/scope expansion
NO credential acquisition/harvesting
NO raw credentials in inventory, evidence, logs or errors
```

Additional invariants:

- every outbound method is guarded by an allowlist before dispatch;
- unknown methods are refused;
- ambiguous tool semantics become `UNKNOWN`, not guessed-safe;
- protocol/SDK types do not leak into the canonical inventory contract;
- `dare-security-evidence` remains MCP-agnostic and dependency-inward;
- enumeration is bounded by pages/items/bytes/depth/time;
- discovered URIs and external schema `$ref` values are not recursively dereferenced during passive discovery;
- HTTP redirects must not silently expand operator-approved scope;
- STDIO process execution must not use shell interpolation by default.

## Required validation baseline

At minimum:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Task-specific schema, contract, integration, redaction, compatibility and passive-method-trace gates defined in the execution specs are also mandatory.

## Critical final proof

Before the cycle can be marked DONE, automated evidence must demonstrate:

```text
set(methods_received_by_lab) subset_of Cycle002Allowlist
```

and explicitly prove absence of:

```text
tools/call
resources/read
prompts/get
```

The final proof must also map the approved Design acceptance criteria to concrete tests/files/results.

## Scope exclusions

This approval does not authorize:

- active exploitation or adversarial tool invocation;
- AuthZEN/COAZ-MCP conformance vectors (reserved for the next cycle);
- prompt-injection attacks;
- attack graph implementation;
- credential harvesting/acquisition;
- database/SaaS/control-plane implementation;
- customer-specific code, findings, URLs, credentials or confidential architecture;
- copying proprietary NEXORA or DARE Runtime code into this Apache-2.0 repository without an explicit IP/licensing decision.

## Completion handoff

When execution is complete, the implementation agent must return with:

- all 12 task statuses;
- implementation commits/diff within PR #6;
- validation output;
- dependency/security audit result;
- protocol compatibility results;
- passive-method trace proof;
- any deviations or unresolved risks;
- final task-012 acceptance matrix.

Cycle 002 becomes DONE only after final DARE Review accepts that evidence.
