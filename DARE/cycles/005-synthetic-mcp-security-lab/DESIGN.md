# Cycle 005 — Synthetic MCP Security Lab & Scenario Corpus

**Status:** APPROVED FOR EXECUTION  
**Cycle:** 005  
**Name:** Synthetic MCP Security Lab & Scenario Corpus  
**Branch:** `agent/cycle-005-synthetic-mcp-security-lab`  
**Approval:** APPROVED — see `APPROVAL.md`.

## Context

The first four cycles established the core security engine:

```text
Cycle 001 — Evidence Kernel
Cycle 002 — Passive MCP Discovery
Cycle 003 — Authorization-to-Execution Integrity
Cycle 004 — CI Security Gate
```

The project can now:

```text
observe
+
validate
+
prove
+
automate
```

The next gap is controlled reference behavior.

Before benchmarking real MCP implementations or constructing higher-level attack graphs, the project needs a deterministic corpus of scenarios where the expected security outcome is known in advance.

## Problem

A scanner or validator is difficult to trust if it is only tested against happy-path fixtures.

The project needs intentionally vulnerable and secure implementations for the same security property so that the engine can prove:

```text
secure implementation     -> expected PASS
vulnerable implementation -> expected FAIL
ambiguous implementation  -> expected INCONCLUSIVE
invalid harness/config     -> expected ERROR
```

The corpus must also remain safe to execute in CI.

It must never require:

- real customer systems;
- production targets;
- real credentials;
- destructive operations;
- sensitive data;
- external infrastructure.

## Goal

Create a reusable synthetic MCP security lab and scenario corpus that:

1. models security properties as deterministic scenarios;
2. provides secure/vulnerable implementation pairs;
3. maps each scenario to expected evidence;
4. exercises existing Cycle 001–004 capabilities;
5. supports local and CI execution;
6. covers modern MCP security surfaces;
7. provides a safe substrate for future benchmark, attack-graph, and adversarial-validation cycles.

## Core principle

> **Known security property + known implementation state + known expected evidence = trustworthy regression scenario.**

The lab is not merely demo code.

It is a reference oracle for the security engine.

## Product outcome

The project should be able to run something conceptually equivalent to:

```text
dare-agent-security validate-lab
```

or an existing CLI-compatible equivalent, without creating a parallel engine.

Exact command naming must be reconciled with the merged CLI in Task 001.

The result should include:

```text
scenario id
security property
implementation variant
expected verdict
observed verdict
evidence reference
standards mappings
```

## Scenario model

Each scenario must define:

```text
Scenario
├── metadata
├── security property
├── applicable MCP revision/profile
├── secure implementation
├── vulnerable implementation
├── preconditions
├── test vector
├── expected evidence
├── expected verdict
├── coverage status
├── standards mappings
└── retest rule
```

## Initial scenario families

The first corpus should cover at least these families.

### MCP-LAB-001 — Passive discovery boundary

Secure:
- discovery/list methods allowed;
- active/state-changing operations blocked in passive mode.

Vulnerable:
- discovery path allows or dispatches active operations.

Expected:
- secure => PASS;
- vulnerable => FAIL.

### MCP-LAB-002 — Missing per-tool authorization

Secure:
- authorization decision occurs per operation/tool.

Vulnerable:
- global authentication is mistaken for authorization.

Expected:
- unauthorized tool invocation => FAIL on vulnerable variant.

### MCP-LAB-003 — Confused deputy

Secure:
- principal, agent identity, and downstream authority remain distinct.

Vulnerable:
- privileged service identity is reused without binding to requesting principal/action.

Expected:
- unauthorized delegated action => FAIL.

### MCP-LAB-004 — Tool name mutation after PERMIT

Secure:
- final tool name is rebound/re-evaluated before execution.

Vulnerable:
- permit for tool A is reused for tool B.

Expected:
- vulnerable variant => FAIL.

### MCP-LAB-005 — Argument mutation after PERMIT

Secure:
- mapped arguments are included in operation binding.

Vulnerable:
- authorization is performed before a security-relevant argument mutation.

Expected:
- vulnerable variant => FAIL.

### MCP-LAB-006 — Trusted-context mutation

Secure:
- trusted context included in authorization projection/binding.

Vulnerable:
- tenant/principal/trusted context can change after PERMIT.

Expected:
- vulnerable variant => FAIL.

### MCP-LAB-007 — Header/body semantic divergence

Secure:
- routing/authorization identity remains consistent with parsed final MCP operation.

Vulnerable:
- authorization layer trusts one representation while execution interprets another.

Expected:
- mismatch => FAIL.

### MCP-LAB-008 — Authorization issuer validation failure

Secure:
- authorization issuer is validated according to the selected supported profile.

Vulnerable:
- issuer confusion or unchecked issuer semantics permit credential/token misuse.

Expected:
- vulnerable variant => FAIL.

### MCP-LAB-009 — Credential issuer reuse

Secure:
- client credentials remain bound to the intended authorization server/issuer context.

Vulnerable:
- credentials are reused across issuer boundaries.

Expected:
- vulnerable variant => FAIL.

### MCP-LAB-010 — MRTR authorization mutation

Secure:
- additional input introduced during multi-round-trip interaction triggers applicable re-evaluation when authorization-relevant semantics change.

Vulnerable:
- original permit survives changed security-relevant input.

Expected:
- vulnerable variant => FAIL.

## Scenario safety requirements

All scenarios must use:

- synthetic identities;
- synthetic tokens/secrets;
- local-only or repository-contained infrastructure;
- non-destructive resources;
- bounded data;
- no internet dependency for security semantics.

A scenario may simulate a dangerous capability without performing a dangerous action.

Example:

```text
delete_customer
```

may write to an in-memory or temporary synthetic store rather than deleting real data.

## Lab structure

Proposed direction:

```text
labs/
└── mcp-security/
    ├── README.md
    ├── scenarios/
    │   ├── MCP-LAB-001/
    │   │   ├── scenario.yaml
    │   │   ├── secure/
    │   │   └── vulnerable/
    │   ├── MCP-LAB-002/
    │   └── ...
    ├── shared/
    │   ├── identities/
    │   ├── policies/
    │   └── fixtures/
    └── runner/
```

Final paths must follow repository conventions discovered in Task 001.

## Lab contract

Each scenario manifest should include at least:

```yaml
id: MCP-LAB-004
title: Tool name mutation after PERMIT
security_property: AUTHZ_EXECUTION_INTEGRITY
mcp_revision: "2026-07-28"

variants:
  secure:
    expected_status: APPLICABLE
    expected_verdict: PASS
  vulnerable:
    expected_status: APPLICABLE
    expected_verdict: FAIL

standards:
  - source: OpenID/AuthZEN/COAZ-MCP
    status: DRAFT_OR_OPEN_PROPOSAL
  - source: OWASP
    status: INFORMATIVE
```

Exact schema names and standards status must be reconciled with the current repository.

## Deterministic evidence

A scenario result must include:

```text
scenario id
variant
harness version
target/scenario version
preconditions
expected
observed
coverage status
verdict
evidence path
standards mappings
```

Do not rely on free-form prose to decide whether the scenario passed.

## CI integration

Cycle 004 should be reused.

The lab must run through the existing CI security gate where feasible.

Required matrix:

```text
secure variants
    -> PASS

vulnerable variants
    -> FAIL

ambiguous fixture
    -> INCONCLUSIVE

invalid harness/config
    -> ERROR
```

Expected FAIL scenarios must be asserted as successful tests of the harness.

A vulnerable fixture causing a FAIL is not a broken CI suite.

## Scope

### In scope

- reconcile post-Cycle-004 `main`;
- scenario manifest/schema;
- shared synthetic MCP lab framework;
- secure/vulnerable variants;
- ten initial scenario families;
- deterministic runner/integration with current CLI;
- evidence generation;
- CI matrix;
- standards metadata;
- documentation;
- final proof.

### Out of scope

- production/customer testing;
- large public benchmark corpus;
- internet-scale scanning;
- exploit chains across real infrastructure;
- full Agent Attack Graph;
- SaaS/dashboard;
- Marketplace work;
- enterprise control plane;
- offensive payload collection;
- destructive testing.

## Acceptance criteria

Cycle 005 is complete only when:

1. The real post-Cycle-004 repository state is reconciled.
2. A versioned scenario manifest/schema exists.
3. Secure and vulnerable implementations exist for all required scenario families.
4. Every scenario declares expected status and verdict.
5. Every scenario emits deterministic evidence.
6. Secure variants PASS.
7. Vulnerable variants FAIL for the intended security property.
8. No scenario requires real credentials or customer infrastructure.
9. The entire lab can run locally and in CI.
10. Expected-failure scenarios are asserted deterministically.
11. No test uses LLM prose as the final verdict source.
12. Standards references distinguish FINAL, DRAFT, OPEN_PROPOSAL, and INFORMATIVE material.
13. Scenario data contains no client-specific information.
14. The lab documents limitations and explicitly avoids claims about real-world prevalence.
15. Final DARE proof maps every acceptance criterion to files/tests/results.

## Exit gate

Before `APPROVAL.md` exists, human review must confirm:

- synthetic lab is the correct Cycle 005 priority;
- the initial ten scenario families are appropriate;
- the lab remains local/synthetic;
- standards mappings are informative unless normative status is verified;
- no customer-derived scenario is included without clean-room generalization.

