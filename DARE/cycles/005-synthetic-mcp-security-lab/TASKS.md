# Cycle 005 — Tasks

> Status: **APPROVED FOR EXECUTION**
> Design: `DESIGN.md` (approved)
> Architecture: `BLUEPRINT.md` (approved)
> Approval: `APPROVAL.md`

## task-001 — Reconcile post-Cycle-004 `main`

**Depends on:** none

Inspect:

- merged Cycle 004;
- CLI/action contract;
- evidence schemas;
- current labs;
- current MCP SDK/protocol support;
- test conventions;
- CI workflows;
- docs/roadmap drift.

Stop if the assumed contracts are absent.

---

## task-002 — Define scenario manifest and schema

**Depends on:** task-001

Create the versioned contract for:

- scenario metadata;
- security property;
- MCP revision/profile;
- variants;
- expected coverage;
- expected verdict;
- safety metadata;
- standards mappings;
- scenario revision.

Add positive and negative schema tests.

---

## task-003 — Build shared synthetic lab framework

**Depends on:** task-001, task-002

Create reusable local-only primitives for:

- synthetic identities;
- synthetic credentials;
- policy decisions;
- local state;
- target startup/teardown;
- deterministic reset;
- bounded request/response fixtures.

No real network dependency for security semantics.

---

## task-004 — Implement passive discovery and authorization-presence scenarios

**Depends on:** task-002, task-003

Implement:

- MCP-LAB-001 Passive discovery boundary
- MCP-LAB-002 Missing per-tool authorization

Each requires:

- secure variant;
- vulnerable variant;
- expected evidence;
- tests.

---

## task-005 — Implement confused-deputy scenario

**Depends on:** task-002, task-003

Implement:

- MCP-LAB-003 Confused deputy

Model:

- human principal;
- agent identity;
- privileged service identity;
- downstream operation.

Secure version preserves authority binding.

Vulnerable version reuses privileged authority without correct principal/action binding.

---

## task-006 — Implement authorization-integrity mutation scenarios

**Depends on:** task-002, task-003

Implement:

- MCP-LAB-004 Tool name mutation
- MCP-LAB-005 Argument mutation
- MCP-LAB-006 Trusted-context mutation

Reuse Cycle 003 canonicalization/binding code.

Do not rebuild it in the lab.

---

## task-007 — Implement modern MCP routing and authorization scenarios

**Depends on:** task-002, task-003

Implement:

- MCP-LAB-007 Header/body semantic divergence
- MCP-LAB-008 Authorization issuer validation failure
- MCP-LAB-009 Credential issuer reuse

Keep all targets synthetic/local.

Map standards status correctly.

---

## task-008 — Implement MRTR authorization-mutation scenario

**Depends on:** task-002, task-003, task-006

Implement:

- MCP-LAB-010 MRTR authorization mutation

The secure version re-evaluates where security-relevant input changes.

The vulnerable version reuses stale authorization.

Use deterministic scripted additional input.

---

## task-009 — Build scenario runner and evidence assertions

**Depends on:** task-004, task-005, task-006, task-007, task-008

Build a thin runner that:

- loads manifests;
- selects secure/vulnerable variant;
- starts target;
- invokes current DARE engine;
- reads evidence;
- compares expected vs observed;
- tears down target.

Important:

```text
expected security FAIL
+
observed security FAIL
=
scenario assertion PASS
```

---

## task-010 — Integrate full corpus with Cycle 004 CI gate

**Depends on:** task-009

Run the corpus through the existing CI path.

Assert:

- all secure variants produce expected PASS;
- all vulnerable variants produce expected FAIL;
- no real credentials/network are used;
- evidence persists to workspace/artifacts as designed;
- repeated execution is stable.

---

## task-011 — Add hostile-fixture and isolation tests

**Depends on:** task-003, task-009

Test the lab itself for:

- state leakage between scenarios;
- fixture ordering dependency;
- malformed manifest;
- malicious metadata strings;
- path traversal in fixture paths;
- accidental external network access;
- secret-like test strings;
- teardown failure.

Fail closed where appropriate.

---

## task-012 — Documentation, scenario catalog, and final DARE proof

**Depends on:** task-010, task-011

Produce:

- lab README;
- scenario catalog;
- secure/vulnerable behavior table;
- standards mapping table;
- limitations;
- contribution guidance for new scenarios;
- final acceptance proof.

Do not claim prevalence or production coverage.
