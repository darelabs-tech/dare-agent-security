# Cycle 022 — Approval

**Cycle:** 022 — Remote Authorized Validation  
**Approval:** DESIGN APPROVED — Blueprint pending  
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
