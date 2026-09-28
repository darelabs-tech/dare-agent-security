# Cycle 022 — Approval

**Cycle:** 022 — Remote Authorized Validation  
**Approval:** APPROVED FOR EXECUTION  
**Approved at:** 2026-09-28  
**Approved by:** Product Owner  
**Base:** `main @ b6f14b9`  
**Branch:** `claude/loving-newton-113zme`

## Approval decision

`DESIGN.md` is approved as the scope contract for Cycle 022, including the Review
decisions recorded in its §13:

1. **Authorization.** It is secured by a digest pin, `--confirm-origin` and the audit
   record. There is no signature in v1. The schema reserves an optional `signature`
   field.
2. **Conversational contract.** There is one closed, DARE-defined contract,
   `dare-conversation`. No model-provider API shape is supported.
3. **Environments.** `environment: production` is refused in v1. Only `lab`, `test` and
   `staging` are accepted.
4. **Side effects.** `tools/call` and every side-effecting method are excluded from v1.
5. **Evidence bridges.** For INCONCLUSIVE and ERROR records, the A2A, MCP Auth and
   supply-chain bridges emit `observed.decision = None` and `observed.result = None`.
   Every bridge validates each record before returning it. This correction is in scope
   for this cycle (§4.8).

## Frozen boundaries

Neither the Blueprint nor execution may, without a new Review:
- give any engine crate a network dependency, or change an engine's no-network
  manifest test;
- let `dare-adversarial` accept `local_only = false`, or let `dare-continuous` schedule
  a remote run;
- send a byte that is not derived from a digest-pinned scenario named in the
  authorization;
- follow redirects, disable TLS verification, or accept a raw URL, header or credential
  on the CLI;
- contact any remote target, or use any secret, in CI;
- add or change a property ID or a profile denominator;
- let any transport outcome produce PASS;
- change the Cycle 018/019/020 evidence bridges beyond §4.8.

## Next step

`/dare-blueprint` produces `BLUEPRINT.md`, `TASKS.md` and `dare-dag.yaml` for Review.
Execution is **not** authorized until the task set is approved.

## Blueprint Review decisions (2026-09-28)

1. **BQ-1.** `dare-mcp-auth-security` gains an additive, network-free
   `scenario_with_observed_resource` API. It maps URLs to opaque ids that preserve
   equality, and records the trust class as `SELF_REPORTED`.
2. **BQ-2.** The `dare-conversation` fields reported by the target (`refusal`,
   `decision`, `fulfillment`, `accepted_authority`) are accepted. Every live PASS that
   relies on one of them is marked as such.
3. **BQ-3.** `rcgen` is added as a dev-dependency only, to generate the lab CA at test
   time.
4. **BQ-4.** Two passes: the live pass is discarded, and the verdict comes only from the
   offline replay of the capture. The engine adapter-trait doc comments name this single
   exception, and the engine code is unchanged.

The `endpoints` refinement to the authorization (Blueprint §4.5) and the rule that A2A
exchange fields not observable from outside the target stay at most INCONCLUSIVE
(Blueprint §6.2) are part of the Blueprint under review.

## Blueprint approval

`BLUEPRINT.md` was approved on 2026-09-28, including AD-01 to AD-17, the `endpoints`
refinement and BQ-1 to BQ-4. `/dare-tasks` now produces `TASKS.md`, `dare-dag.yaml`
and `dare-dag.exec.yaml` for Review. Execution is **not** authorized until that task set
is approved.

## Authorized execution

The task set (`TASKS.md`, `dare-dag.yaml`, `dare-dag.exec.yaml`, 43 tasks) was approved on
2026-09-28. Tasks `task-001` through `task-043` are approved for execution in the
dependency order of `dare-dag.exec.yaml`. No additional human approval is required
between tasks while execution stays inside the frozen boundaries above.

The executor must stop and record the discrepancy for Review instead of proceeding if a
task would require any of the following:
- crossing a frozen boundary;
- contacting any host other than the loopback REMOTE-LAB during development or CI;
- adding a runtime dependency beyond those in BLUEPRINT §2;
- changing an engine's verdict semantics.
