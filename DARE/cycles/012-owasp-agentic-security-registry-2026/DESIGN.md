# Cycle 012 - OWASP Agentic Security Registry 2026

**Status:** DESIGN READY FOR REVIEW  
**Base branch:** `main`  
**Baseline:** v1.0-rc1 / Cycles 001-011 delivered  
**Branch:** `agent/cycle-012-owasp-agentic-security-registry-2026`  
**Approval:** PENDING

## 1. Purpose

Cycle 012 expands DARE Agent Security from an MCP/AuthZ-focused baseline into a standards-grounded Agentic AI Security property registry aligned to the OWASP Top 10 for Agentic Applications 2026 and compatible with the emerging OWASP Agent Control Standard.

This cycle is a **registry, schema, coverage and conformance-foundation cycle**. It does not implement full dynamic exploitation, generalized prompt-injection execution, remote state-changing testing, autonomous red teaming, or a new control plane.

## 2. Why this cycle exists

Cycle 011 stated that Cycle 012 should follow real product evidence. This cycle is opened by explicit Product Owner override because the external security baseline materially changed after Cycle 011 design: OWASP published the 2026 Agentic Top 10 and Agent Control Standard material, creating a concrete standards-compatibility requirement for the product.

The override does not claim customer telemetry or field evidence that does not exist. It records an external standards trigger plus explicit human authorization.

## 3. North star

> Every agentic security property must be explicit, versioned, standards-referenced, machine-readable, testable, evidence-aware, and incapable of silently becoming PASS when it was not actually tested.

## 4. Scope

Cycle 012 MUST define the registry foundation for these Agentic AI risk families:

1. Agent Goal Hijacking
2. Tool Misuse and Exploitation
3. Identity and Privilege Abuse
4. Agentic Supply Chain Vulnerabilities
5. Unexpected Code Execution
6. Memory and Context Poisoning
7. Insecure Inter-Agent Communication
8. Cascading Failures
9. Human-Agent Trust Exploitation
10. Rogue Agents

It MUST also preserve existing MCP/AuthZ properties and map them into the broader agentic taxonomy without breaking v1 behavior.

## 5. Required outputs

The cycle must deliver:

- Agentic property ID namespace and schema evolution strategy;
- versioned Agentic Security Registry;
- OWASP Agentic Top 10 2026 crosswalk;
- initial Agentic Security baseline profile;
- compatibility mapping from existing MCP properties;
- applicability predicates for agentic systems;
- evidence requirements per property;
- supported validation modes per property;
- coverage-engine compatibility;
- deterministic fixtures for registry/profile validation;
- machine-readable standards provenance;
- CLI/profile compatibility proof;
- documentation for operators and contributors.

## 6. Property namespace

The current property schema accepts only IDs beginning with `MCP.`. Cycle 012 must generalize this safely.

Preferred namespaces:

```text
MCP.*
AGENT.*
RAG.*        # reserved for future cycle
MEMORY.*     # reserved for future cycle
A2A.*        # reserved for future cycle
```

Cycle 012 should actively introduce `AGENT.*` only. Reserved namespaces may be documented but must not gain unsupported properties.

Example properties:

```text
AGENT.GOAL.INSTRUCTION_INTEGRITY
AGENT.TOOL.AUTHORIZATION_BOUNDARY
AGENT.TOOL.OUTPUT_TRUST_BOUNDARY
AGENT.IDENTITY.DELEGATION_INTEGRITY
AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION
AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE
AGENT.CODE_EXECUTION.BOUNDARY
AGENT.MEMORY.CONTEXT_INTEGRITY
AGENT.A2A.MESSAGE_AUTHENTICITY
AGENT.FAILURE.RETRY_AMPLIFICATION
AGENT.HUMAN_APPROVAL.INTENT_BINDING
AGENT.ROGUE.CAPABILITY_DRIFT
```

Names are illustrative until task-level review freezes the registry.

## 7. Registry semantics

Each property MUST include at least:

```text
id
title
category
description
applicability predicates
supported validation modes
evidence requirement
standards mappings
maturity/status
```

Cycle 012 must not add vague prose-only risks that cannot be connected to a testable security invariant.

## 8. Categories

The property schema should evolve beyond the current MCP-focused category enum.

Candidate Agentic categories:

```text
GOAL_INTEGRITY
TOOL_SECURITY
IDENTITY
AUTHENTICATION
AUTHORIZATION
DELEGATION
PRIVILEGE
SUPPLY_CHAIN
CODE_EXECUTION
MEMORY_CONTEXT
INTER_AGENT
FAILURE_CONTAINMENT
HUMAN_OVERSIGHT
ROGUE_BEHAVIOR
EVIDENCE
```

Existing categories remain supported for backward compatibility.

## 9. Applicability predicates

Current predicates are primarily MCP-oriented. Cycle 012 must introduce a closed, deterministic predicate set for agentic applicability.

Candidate predicates:

```text
agent_present
tools_present
memory_present
rag_present
multi_agent_present
code_execution_present
human_approval_present
delegated_identity_present
external_components_present
stateful_agent_present
runtime_dynamic_allowed
```

No arbitrary expression language or executable policy is introduced in this cycle.

## 10. Standards provenance

Every new property must identify its source and exact risk/control relationship.

Supported source labels should include at minimum:

```text
OWASP_AGENTIC_TOP10_2026
OWASP_AGENT_CONTROL_STANDARD
MCP
AUTHZEN
COAZ_MCP
CWE
DARE
```

A standards mapping does not imply normative equivalence unless explicitly documented.

## 11. Baseline profile

Create an initial profile:

```text
agentic-security-baseline-2026
```

The profile must contain a deliberately small, defensible set of REQUIRED and CONDITIONAL properties. It must not claim complete coverage of every implementation pattern.

The baseline must be usable by the existing coverage engine.

## 12. Backward compatibility

Cycle 012 must preserve:

- `mcp-security-baseline` behavior;
- existing Cycle 001 evidence contracts;
- existing Cycle 006 coverage math;
- existing CLI exit semantics;
- existing reports and artifact layout unless additive fields are backward-compatible;
- offline/confidential defaults from Cycle 011.

Existing MCP property IDs must not be renamed merely for taxonomy aesthetics.

## 13. Coverage semantics

The existing rule remains authoritative:

```text
APPLICABLE without verdict -> NOT_TESTED
BLOCKED never becomes NOT_APPLICABLE
```

New Agentic properties must obey the same fail-closed semantics.

Coverage may report both:

```text
overall coverage
required coverage
risk-family coverage
```

Risk-family coverage is additive and must not alter existing denominator semantics without a versioned contract.

## 14. Evidence semantics

A confirmed security verdict must remain evidence-backed.

Cycle 012 must define which evidence classes are valid for registry-level properties:

```text
STATIC
PASSIVE_RUNTIME
DYNAMIC_AUTHORIZED
SYNTHETIC
POLICY
TRACE
CONFIGURATION
```

The cycle may define metadata contracts but must not create a generalized dynamic attack engine.

## 15. Threat-model constraints

The registry itself is security-sensitive input.

Tests must cover:

- property injection;
- duplicate IDs;
- unknown categories;
- unknown predicates;
- malformed standards mappings;
- schema downgrade;
- profile references to unknown properties;
- registry/profile version mismatch;
- risk-family spoofing;
- untrusted documentation strings;
- deterministic ordering;
- stable canonical serialization where hashes are used.

## 16. CLI behavior

Existing public commands remain stable.

Cycle 012 may enable:

```bash
dare-agent-security validate coverage --profile agentic-security-baseline-2026 ...
```

It MUST NOT add placeholder commands such as `validate prompt-injection` unless an actual validation engine exists.

## 17. Out of scope

Explicitly excluded:

- active prompt-injection engine;
- indirect prompt-injection execution;
- Garak/PyRIT integration;
- remote authorized dynamic execution;
- memory poisoning implementation;
- RAG security engine;
- A2A active testing;
- runtime enforcement product;
- new SaaS/control plane;
- arbitrary policy language;
- LLM-as-final-judge verdicts;
- autonomous exploit-chain generation.

These are candidate later cycles.

## 18. Acceptance criteria

1. Cycle 012 branch is isolated from `main`.
2. Existing v1.0-rc1 behavior remains compatible.
3. Property schema supports `AGENT.*` without breaking `MCP.*`.
4. Agentic categories are versioned and closed.
5. Agentic applicability predicates are versioned and closed.
6. OWASP Agentic Top 10 2026 risk families are represented.
7. Each new property is testable as a security invariant.
8. Each new property has standards provenance.
9. Existing MCP properties remain unchanged unless a backward-compatible metadata addition is explicitly approved.
10. `agentic-security-baseline-2026` exists.
11. The baseline uses REQUIRED/CONDITIONAL/OPTIONAL deliberately.
12. Coverage engine can evaluate the Agentic baseline.
13. Unknown properties fail closed.
14. Unknown predicates fail closed.
15. Duplicate IDs fail validation.
16. Invalid standards mappings fail validation.
17. Existing `mcp-security-baseline` regression remains green.
18. Existing coverage denominator semantics remain unchanged.
19. Registry/profile fixtures include secure, malformed and adversarial cases.
20. JSON schemas remain local/offline-validatable.
21. No schema fetch from network is required.
22. CI includes registry/profile compatibility gates.
23. Operator documentation explains what registry coverage does and does not prove.
24. Reports do not claim untested Agentic properties are secure.
25. Confidential/offline mode remains fail-closed.
26. No new active attack capability is introduced.
27. No arbitrary LLM verdict authority is introduced.
28. Final proof maps every acceptance criterion to files/tests/results.
29. `APPROVAL.md` remains absent until explicit Product Owner approval.

## 19. Definition of done

Cycle 012 is complete when DARE Agent Security can express and evaluate coverage against a defensible 2026 Agentic Security registry while preserving the deterministic, evidence-first and fail-closed properties of Cycles 001-011.
