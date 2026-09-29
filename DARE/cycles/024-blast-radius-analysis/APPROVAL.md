# Cycle 024 — Approval

**Cycle:** 024 — Blast-Radius Analysis  
**Approval:** APPROVED FOR EXECUTION  
**Approved at:** 2026-09-28  
**Approved by:** Product Owner  
**Base:** `main @ d125081`  
**Branch:** `claude/loving-newton-113zme`

## Approval decision

`DESIGN.md` is approved as the scope contract for Cycle 024, with the recommended option
for every Review question in its §13:

1. **Q1 (a).** A new crate, `dare-blast-radius`, depends only on `dare-attack-graph`.
   The authority-continuity rule moves from `dare-attack-path` into
   `dare_attack_graph::v2`, and both crates call that one implementation.
2. **Q2 (a).** The input is a v2 `attack-graph.json` only. Graph construction stays
   `validate attack-paths`.
3. **Q3 (a).** No impact weighting. Impact is counts by target class, tenant and trust
   boundary, plus witness routes.
4. **Q4 (a).** The A2A delegated-subject limitation stays out of scope. Reach inherits
   Cycle 023 continuity unchanged.
5. **Q5 (a).** The remediation delta (RF-10) is SHOULD, bounded to 64 failed edges, and
   reported as counts only.
6. **Q6 (b).** Product integration (RF-14) is out of scope for v1.
7. **Q7 (a).** Exactly two views: structural and uncontained.

## Frozen boundaries

Neither the Blueprint nor execution may, without a new Review:
- change an engine crate (013–022), its verdict semantics or its artifacts;
- change the output of `validate attack-paths` (Cycle 023) or of
  `validate attack-graph --facts` (Cycle 008) for any existing input;
- change the continuity rules C1–C6 or the control-state rule;
- report a node `CONTAINED` unless no uncontained route to it exists within the bounds,
  and the uncontained search was not truncated;
- add a risk score, probability, likelihood or weighting;
- give `dare-blast-radius` a network dependency, an engine dependency or a dependency on
  `dare-attack-path`, or let it execute, send or schedule anything;
- add or change a property ID or a profile denominator.

## Blueprint approval (2026-09-28)

`BLUEPRINT.md` is approved, including AD-01 to AD-10, with the recommended option for
each Review item:

1. **BQ-1.** The witness route is the first route the breadth-first search reaches, over
   adjacency sorted by `(target id, edge id)`.
2. **BQ-2.** A third exposure state, `CONTAINMENT_UNKNOWN`. `CONTAINED` is claimed only
   within `max_depth`, and only when the uncontained search was not truncated.
3. **BQ-3.** Search states are keyed by `(node, principal, actors)`.
4. **BQ-4.** A seed without a tenant has no cross-tenant targets (as Cycle 023 R-9).
5. **BQ-5.** Exit 2 when any target is `EXPOSED` or any search was truncated; exit 0 when
   every reached target is `CONTAINED` and nothing was cut.

## Authorized execution

The task set (`TASKS.md`, `dare-dag.yaml`, `dare-dag.exec.yaml`, 28 tasks) was approved
on 2026-09-29. Tasks `task-001` through `task-028` are approved for execution in the
dependency order of `dare-dag.exec.yaml`. No further human approval is needed between
tasks as long as execution stays inside the frozen boundaries above.

The executor must stop and record the discrepancy for Review, instead of proceeding, if
a task would require any of the following:
- crossing a frozen boundary;
- changing an engine crate;
- adding a third-party dependency;
- changing a Cycle 023 or Cycle 008 output;
- changing continuity or control-state semantics.

Merging to `main` requires human approval.
