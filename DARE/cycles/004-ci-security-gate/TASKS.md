# Cycle 004 — Tasks

> Status: **APPROVED FOR EXECUTION**
> Design: `DESIGN.md` (approved)
> Architecture: `BLUEPRINT.md` (approved)
> Approval: `APPROVAL.md`

## task-001 — Reconcile post-Cycle-003 `main`

**Depends on:** none

Inspect the actual merged repository and freeze the baseline for Cycle 004.

Deliver:

- exact Cycle 003 merge state;
- CLI binary/package names;
- supported non-interactive commands;
- evidence output contract;
- current labs/fixtures;
- existing CI;
- current Rust toolchain/MSRV;
- documentation drift list.

Gate:

If Cycle 003 acceptance is missing from `main`, stop Cycle 004 planning execution and report the discrepancy.

---

## task-002 — Define deterministic CI result contract

**Depends on:** task-001

Specify:

- supported Action modes;
- aggregate verdict semantics;
- interaction with `PASS`, `FAIL`, `INCONCLUSIVE`, `ERROR`;
- process success/failure behavior;
- output directory contract;
- GitHub outputs;
- behavior for no evidence / partial evidence.

Do not invent GitHub-specific security verdicts.

---

## task-003 — Verify Action packaging architecture and threat model

**Depends on:** task-001

Evaluate Docker container Action as the primary packaging candidate.

Verify:

- runner compatibility;
- repository build requirements;
- action metadata constraints;
- workspace mapping;
- build time;
- shell/entrypoint threat surface;
- required permissions.

Deliver architecture decision and threat-model notes before implementation.

---

## task-004 — Make the CLI CI-safe and non-interactive

**Depends on:** task-002

Ensure the existing CLI can be invoked deterministically by automation.

Implement only the minimum additive changes required for:

- explicit machine output path;
- aggregate verdict result;
- stable non-interactive behavior;
- deterministic exit behavior;
- no prompts.

Do not add a new `ci` command unless current CLI structure requires it and the design review approves it.

---

## task-005 — Implement the thin GitHub Action adapter

**Depends on:** task-002, task-003

Create Action metadata and packaging.

Requirements:

- bounded mode enum;
- explicit target;
- workspace-contained output path;
- safe argument passing;
- no `eval`;
- no arbitrary command passthrough;
- no write-capable GitHub token requirement.

The Action must invoke the CLI rather than duplicate security logic.

---

## task-006 — Integrate evidence, outputs, and job summary

**Depends on:** task-004, task-005

Expose:

- aggregate verdict;
- evidence path;
- summary path.

Write a concise `GITHUB_STEP_SUMMARY`.

Prove secret-bearing evidence is not emitted to GitHub outputs or summary.

---

## task-007 — Build synthetic Action fixtures

**Depends on:** task-002, task-004

Prepare deterministic local/synthetic cases for:

- PASS;
- FAIL;
- INCONCLUSIVE;
- ERROR.

Reuse existing Cycle 002/003 synthetic infrastructure where possible.

Do not create a second competing lab if the existing one can be extended.

---

## task-008 — Add Action E2E workflow matrix

**Depends on:** task-006, task-007

Invoke the repository Action via `uses: ./`.

Assert:

- secure fixture passes;
- failing fixture fails as expected;
- error configuration fails as expected;
- inconclusive behavior matches configured/default policy;
- evidence exists in workspace;
- outputs match evidence.

No external/customer target.

---

## task-009 — Security hardening and hostile-input tests

**Depends on:** task-003, task-005, task-006

Test:

- shell metacharacters in target values;
- traversal attempts in output path;
- control/Markdown content in target metadata;
- unknown mode;
- unsupported protocol behavior;
- accidental secret strings;
- redirect/scope-expansion attempts where applicable.

Prove inputs remain data and the Action does not gain a code-execution surface.

---

## task-010 — Documentation and project-state reconciliation

**Depends on:** task-008, task-009

Update documentation to reflect:

- Cycles 001–003 delivered;
- Cycle 004 Action capability;
- pre-release status;
- minimum permissions;
- passive/default safety behavior;
- pinned-ref recommendation;
- example workflow;
- evidence artifact handoff.

Do not declare Marketplace availability or stable `v1`.

---

## task-011 — Final DARE proof and release-candidate handoff

**Depends on:** task-010

Produce final evidence that maps every Cycle 004 acceptance criterion to:

- file;
- test;
- command;
- result.

Confirm:

- no approval bypass;
- no out-of-scope active testing;
- no secret leak;
- no domain logic duplicated in Action layer;
- no stable-release claim.

Cycle 004 can be marked implemented only after this proof passes.

Release/tagging remains a separate human decision.
