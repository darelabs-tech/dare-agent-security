# Cycle 021 — Approval

**Cycle:** 021 — Adaptive Multi-Turn Adversarial Execution  
**Approval:** APPROVED FOR EXECUTION  
**Approved at:** 2026-09-27  
**Approved by:** Product Owner  
**Base:** `main @ 4ca06b2`  
**Execution branch:** `claude/loving-newton-113zme`

## Approval decision

`DESIGN.md` is approved as the scope contract for Cycle 021, including the Review
decisions recorded in its §13:

1. Multi-turn properties are additive IDs inside the existing `AGENT.GOAL`,
   `AGENT.IDENTITY`, `AGENT.HUMAN_APPROVAL` and `AGENT.MEMORY` families. No
   `AGENT.MULTI_TURN.*` namespace is created.
2. The hard maxima are 32 turns per conversation, 256 nodes and 64 enumerable paths per
   strategy graph. Input may only lower them.
3. Strategy graphs are strictly acyclic (DAG) in v1.
4. The published MULTITURN-LAB corpus is synthetic-only. The REPLAY mode may read
   transcripts that a user supplies locally.

## Blueprint approval

`BLUEPRINT.md` was approved on 2026-09-27, including the Action-image rule (AD-10).
`TASKS.md`, `dare-dag.yaml` and `dare-dag.exec.yaml` (37 tasks) are proposed for review.

## Authorized execution

The task set (`TASKS.md`, `dare-dag.yaml`, `dare-dag.exec.yaml`, 37 tasks) was approved on
2026-09-27. Tasks `task-001` through `task-037` are approved for execution in the
dependency order defined by `dare-dag.exec.yaml`. No additional human approval is
required between tasks while execution stays inside the frozen boundaries below.

The executor must stop and record the discrepancy for Review instead of proceeding if a
task would require any of the following:
- a network, credential, LLM or turn-generation capability;
- changing an existing property ID or an earlier profile denominator;
- weakening a PASS rule so that missing, unclassifiable or incomplete evidence can PASS;
- taking single-turn verdict authority away from Cycles 013–020;
- breaking the Action image build.

## Frozen boundaries (already binding for the Blueprint)

- **Closed adaptivity:** every turn is a pre-authored, digest-bound node of an approved
  DAG. Nothing is generated, mutated, templated or paraphrased at run time.
- **No LLM or remote target:** no model, provider, endpoint or credential. Live and
  remote targets belong to Cycle 022.
- **No false PASS:** a stop before a terminal node, an `UNCLASSIFIABLE` observation,
  missing evidence or an engine fault never yields PASS.
- **Cycle 009 controls stay in force:** every LOCAL_SYNTHETIC turn passes through
  `kill_switch` and `BudgetState`.
- **Ownership:** single-turn verdict authority stays with Cycles 013–020. Cycle 006 owns
  coverage math, and Cycle 018 owns concrete-FAIL aggregation.
- **Out of scope:**
  - Cycle 022 — remote authorized validation;
  - Cycle 023 — attack-path construction;
  - Cycle 024 — blast-radius analysis;
  - Cycle 025 — runtime OpenTelemetry security.
