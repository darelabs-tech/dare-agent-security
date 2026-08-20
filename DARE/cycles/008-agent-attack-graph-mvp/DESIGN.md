# Cycle 008 — Agent Attack Graph MVP

**Status:** APPROVED FOR EXECUTION  
**Cycle:** 008  
**Name:** Agent Attack Graph MVP  
**Base branch:** `main`  
**Planning baseline:** Cycles 001–007 delivered on `main`  
**Branch:** `agent/cycle-008-agent-attack-graph-mvp`  
**Approval:** APPROVED (2026-08-20) — see `APPROVAL.md`.

## Context

Delivered foundation:

```text
001 Evidence Kernel
002 Passive MCP Discovery
003 Authorization-to-Execution Integrity
004 CI Security Gate
005 Synthetic MCP Security Lab
006 Assessment Profiles & Coverage Engine
007 MCP Security Benchmark & Corpus Methodology
```

The project can now discover, plan, validate, produce deterministic evidence, measure coverage, run in CI, self-test against synthetic ground truth, and benchmark public MCP implementations reproducibly.

Cycle 008 adds a relationship model for authority and reachability.

## Problem

Agentic systems compose trust and authority across multiple boundaries:

```text
Human
  ↓
Agent
  ↓
Delegated Authority
  ↓
MCP Server
  ↓
Tool
  ↓
Credential
  ↓
Downstream API
  ↓
Resource
```

A flat finding list cannot express how individually small weaknesses combine into a high-impact path.

## Goal

Create an **Agent Attack Graph MVP** that transforms existing DARE artifacts into:

```text
Nodes
+
Edges
+
Authority Context
+
Evidence Bindings
+
Coverage State
+
Attack Paths
+
Deterministic Graph Artifacts
```

Cycle 008 consumes existing contracts. It must not create a parallel evidence, verdict, coverage, or security-property system.

## Core principles

1. **Evidence-backed edges.** Every relationship has an explicit evidence state.
2. **Edge state is not verdict.** Graph evidence must not reuse PASS/FAIL semantics.
3. **Inference remains visible.** Inferred relationships are never presented as proven exploitation.
4. **Deterministic construction.** Identical source artifacts must produce identical graph output.
5. **Authority, not only connectivity.** The graph must model who can cause what under which identity, delegation, capability, credential, tenant, and authorization context.
6. **Analysis first.** Cycle 008 does not autonomously execute attack paths; controlled validation is deferred to Cycle 009.

## Graph object model

Introduce:

```text
AttackGraph
AttackGraphNode
AttackGraphEdge
AttackPath
```

### AttackGraph

```yaml
schema_version: "1"

graph:
  id: graph-0001
  target_id: target-0001
  target_version: <sha>
  generated_at: <timestamp>

  sources:
    inventory_digest: sha256:...
    assessment_plan_digest: sha256:...
    evidence_bundle_digest: sha256:...
    benchmark_record_digest: sha256:...
```

## Initial node taxonomy

```text
HUMAN
AGENT
IDENTITY
DELEGATED_AUTHORITY
MCP_SERVER
CAPABILITY
TOOL
CREDENTIAL
DOWNSTREAM_SERVICE
RESOURCE
DATA
TENANT
POLICY_DECISION_POINT
POLICY_ENFORCEMENT_POINT
```

Exact types must be reconciled against the actual post-Cycle-007 schemas.

## Initial edge taxonomy

```text
AUTHENTICATES_AS
DELEGATES_TO
CAN_INVOKE
CALLS
USES_CREDENTIAL
AUTHORIZED_BY
ENFORCED_BY
READS
WRITES
DELETES
TRANSFERS_TO
BELONGS_TO_TENANT
CROSSES_TRUST_BOUNDARY
CAN_REACH
```

Prefer semantic edges over a generic `CONNECTED_TO`.

## Edge evidence status

```text
OBSERVED
STATICALLY_PROVEN
INFERRED
NOT_TESTED
```

Semantics:

- `OBSERVED`: runtime evidence directly demonstrates the relationship.
- `STATICALLY_PROVEN`: deterministic source/config analysis proves the relationship.
- `INFERRED`: relationship is plausible from available facts but not proven.
- `NOT_TESTED`: possible relationship was identified but not evaluated.

## Stable node identity

Recommended form:

```text
node:<type>:<stable-local-id>
```

Examples:

```text
node:agent:customer-support
node:mcp-server:crm-mcp
node:tool:customer.export
node:credential:crm-service-token
node:resource:customer-records
```

A node should retain source provenance where available:

```text
source path
symbol
wire name
configuration key
```

## Stable edge identity

A deterministic edge key should include:

```text
source_node_id
+
edge_type
+
target_node_id
+
normalized_authority_context
```

Reuse canonicalization/digest conventions from Cycles 006–007 where possible.

## Authority context

Relevant edges should support:

```text
principal
agent identity
service identity
delegated authority
tenant
credential
authorization decision
scope
```

Example:

```yaml
edge:
  type: CAN_INVOKE
  source: node:agent:support-agent
  target: node:tool:customer.export

  authority:
    principal: user:123
    agent_identity: support-agent
    delegated: true
    tenant: tenant-a
    credential: node:credential:crm-token
```

## Evidence binding

`OBSERVED` and `STATICALLY_PROVEN` edges must reference deterministic evidence.

```yaml
evidence:
  status: OBSERVED
  evidence_ids:
    - evidence-123
```

`INFERRED` edges require explicit rationale and source facts.

```yaml
evidence:
  status: INFERRED
  rationale: >
    Tool implementation imports a credential provider and invokes the CRM
    client, but runtime execution was not observed.
  source_facts:
    - inventory.tool.customer.export
    - source.crm_client_call
```

## Coverage integration

The graph must preserve Cycle 006 dimensions where relevant:

```text
applicability
scope
execution
verdict
```

Example:

```yaml
security:
  property: MCP.AUTHZ.PER_OPERATION
  applicability: APPLICABLE
  scope: IN_SCOPE
  execution: BLOCKED
  verdict: null
```

A visually complete graph must never imply complete assurance.

## Property-to-graph mapping

Examples:

```text
MCP.AUTHZ.PER_OPERATION
    -> CAN_INVOKE / AUTHORIZED_BY

MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME
    -> CALLS / execution binding

MCP.IDENTITY.CONFUSED_DEPUTY
    -> authority-context inconsistency

MCP.INVENTORY.COMPLETENESS
    -> graph completeness prerequisite
```

Exact IDs must use the real registry on `main`.

## Attack Path

An Attack Path is an ordered sequence:

```text
node
edge
node
edge
...
node
```

Example:

```text
Human
  --DELEGATES_TO-->
Agent
  --CAN_INVOKE-->
Tool
  --USES_CREDENTIAL-->
Credential
  --CAN_REACH-->
CRM API
  --READS-->
Customer Data
```

### Path evidence state

Recommended rule:

```text
if any edge == NOT_TESTED
    path_status = NOT_TESTED
else if any edge == INFERRED
    path_status = INFERRED
else if all edges in {OBSERVED, STATICALLY_PROVEN}
    path_status = PROVEN
```

`PROVEN` is a path-evidence state, not a security verdict.

### Deterministic impact factors

Annotate, but do not collapse into a speculative score:

```text
cross_tenant
uses_privileged_credential
reaches_sensitive_resource
contains_destructive_capability
contains_failed_security_property
contains_authorization_mutation
```

## Path queries

MVP should support bounded deterministic queries such as:

```text
all paths from AGENT to RESOURCE
all paths using a CREDENTIAL
all cross-tenant paths
all paths containing FAIL property results
all paths with INFERRED edges
all paths reaching DESTRUCTIVE capabilities
all paths where authorized and executed identities differ
```

Exact CLI/API surface must be reconciled with the existing application.

## Graph completeness

The graph is only as complete as its inventory and assessment coverage.

Surface at least:

```text
inventory_complete: true|false|unknown
unresolved_edges: N
not_tested_edges: N
inferred_edges: N
```

Do not invent a single completeness percentage unless semantics are rigorously defined.

## Graph provenance

Every graph artifact must record:

```text
target ID/version
engine commit
property registry version/digest
profile version/digest
assessment plan digest
evidence bundle digest
benchmark record digest if present
graph schema version
graph generator version
```

## Serialization

Canonical representation:

```text
JSON
```

Derived views may include:

```text
Mermaid
DOT
GraphML (optional)
```

JSON remains canonical; renderers are views.

## Visualization

Cycle 008 does not need a SaaS UI.

Generated views must show evidence state using labels, not color alone:

```text
[OBSERVED]
[STATICALLY_PROVEN]
[INFERRED]
[NOT_TESTED]
```

## Benchmark integration

Cycle 007 Benchmark Records may be consumed when available, but must remain optional for single-target graph construction.

This enables future research such as:

```text
how many targets expose credential-to-resource paths?
how many paths contain inferred authority?
how many FAIL findings participate in multi-hop paths?
```

## Synthetic graph fixtures

### GRAPH-LAB-001 — Direct safe read path

```text
Agent -> Tool -> Resource
```

Expected: all edges proven, no tenant crossing, no destructive capability.

### GRAPH-LAB-002 — Confused deputy path

```text
Human A -> Agent -> Service Credential B -> Tenant B Resource
```

Expected: authority-context mismatch represented.

### GRAPH-LAB-003 — Inferred credential path

Static evidence suggests credential use but runtime observation is absent.

Expected: `INFERRED` or `STATICALLY_PROVEN` according to deterministic evidence quality.

### GRAPH-LAB-004 — Not-tested destructive path

Inventory exposes destructive capability but ROE prevents dynamic execution.

Expected: path preserves `NOT_TESTED` / blocked security context.

### GRAPH-LAB-005 — Authorization/execution mutation

Expected: graph highlights mismatch between authorized and executed operation identity.

## Security of graph generation

Threats:

- malicious labels;
- Mermaid/DOT injection;
- path explosion;
- huge graph DoS;
- cycles;
- duplicate IDs;
- malformed evidence references;
- arbitrary file/URI links;
- secret leakage in labels.

Controls:

- schema validation;
- escaping;
- node/edge limits;
- max path depth/count;
- safe serialization;
- Cycle 001 redaction reuse;
- no arbitrary URI dereference;
- deterministic ID validation.

## CI integration

CI should validate:

```text
graph schema
deterministic IDs
edge evidence invariants
property mappings
path derivation
weakest-edge path status
redaction
bounds
fixtures
renderer serialization
```

Use small deterministic graph fixtures; do not require the whole benchmark corpus.

## Scope

### In scope

- post-Cycle-007 reconciliation;
- graph schema;
- node/edge taxonomy;
- stable IDs;
- authority context;
- evidence binding;
- Cycle 006 coverage binding;
- property-to-graph mapping;
- deterministic graph builder;
- bounded path engine;
- path evidence state;
- deterministic impact factors;
- provenance/digest;
- canonical JSON;
- Mermaid/DOT views;
- graph-specific fixtures;
- CI regression;
- docs and final proof.

### Out of scope

- autonomous exploitation;
- active attack execution;
- exploit optimization;
- internet-scale graph aggregation;
- SaaS graph UI;
- enterprise fleet graph;
- exploitability probability score;
- continuous graph monitoring.

## Acceptance criteria

1. Post-Cycle-007 `main` reconciled.
2. Versioned Attack Graph schema exists.
3. Versioned node taxonomy exists.
4. Versioned edge taxonomy exists.
5. Stable deterministic node IDs exist.
6. Stable deterministic edge IDs exist.
7. Authority context is represented.
8. `OBSERVED`, `STATICALLY_PROVEN`, `INFERRED`, `NOT_TESTED` are implemented.
9. Edge state is not conflated with verdict.
10. Proven edges reference deterministic evidence.
11. Inferred edges carry rationale/source facts.
12. Cycle 006 applicability/scope/execution/verdict are preserved.
13. Property-to-graph mappings exist for relevant properties.
14. Attack paths are derived deterministically.
15. Path status follows weakest-edge semantics or reviewed equivalent.
16. Graph provenance records source artifact digests.
17. Canonical machine-readable graph output exists.
18. Mermaid/DOT are derived views only.
19. Graph generation is bounded and safe against hostile input.
20. Graph fixtures validate known topology/authority behavior.
21. Authorization/execution mutation is representable.
22. Confused deputy paths are representable.
23. Credential-to-resource paths are representable.
24. `NOT_TESTED`/blocked context remains visible in paths.
25. CI covers determinism and path semantics.
26. Final DARE proof maps all criteria to files/tests/results.
27. `APPROVAL.md` remains absent until explicit human approval.

## Exit gate

Human review must confirm:

- node taxonomy;
- edge taxonomy;
- edge evidence states;
- path-state semantics;
- authority-context fields;
- canonical serialization;
- CLI surface;
- GraphML now vs deferred;
- benchmark integration depth;
- final graph fixture set.
