# Cycle 008 — Blueprint

**Status:** APPROVED FOR EXECUTION  
**Approval:** APPROVED (2026-08-20)

## Dependency statement

Cycle 008 reuses Cycles 001–007.

It must not create parallel:

```text
evidence
verdict
coverage
property registry
benchmark record
```

## Architecture

```text
Cycle 002 Inventory
      +
Cycle 003 Authorization Integrity
      +
Cycle 006 Profile/Coverage
      +
Cycle 001 Evidence
      +
Cycle 007 Benchmark Record (optional)
            ↓
      Graph Fact Extractor
            ↓
      Normalized Graph Facts
            ↓
      Graph Builder
            ↓
      Canonical AttackGraph JSON
            ↓
      Bounded Path Engine
            ↓
      AttackPath[]
            ↓
      Mermaid / DOT Views
```

## Component boundaries

### Graph Fact Extractor
Reads existing DARE artifacts and produces normalized facts.

### Graph Builder
Builds nodes/edges deterministically.

### Path Engine
Derives bounded paths and path evidence state.

### Renderer
Produces non-canonical views.

### Graph Validator
Enforces schema and semantic invariants.

No component decides security verdicts.

## Canonical graph

```yaml
graph:
  metadata: ...
  nodes: [...]
  edges: [...]
  paths: [...]
```

Canonical format: JSON.

## Node candidate

```yaml
node:
  id: node:tool:customer.export
  type: TOOL
  display_name: customer.export

  source:
    target_id: target-001
    file: src/tools/customer.ts
    symbol: exportCustomer

  security:
    state_impact: READ_ONLY
    tenant: tenant-a
```

## Edge candidate

```yaml
edge:
  id: edge:<digest>
  type: CAN_INVOKE
  source: node:agent:support
  target: node:tool:customer.export

  authority:
    principal: user:123
    delegated: true
    credential: node:credential:crm-token

  evidence:
    status: OBSERVED
    evidence_ids:
      - evidence-123

  security:
    properties:
      - MCP.AUTHZ.PER_OPERATION
```

## Edge evidence invariants

```text
OBSERVED
→ evidence_ids required

STATICALLY_PROVEN
→ evidence_ids required

INFERRED
→ rationale + source_facts required

NOT_TESTED
→ reason required
```

## Deterministic edge ID

Digest of normalized:

```text
source
edge type
target
authority context
```

Reuse canonicalization from Cycles 006/007.

## Path engine guards

Required:

```text
max_depth
max_paths
cycle detection
node filters
edge filters
```

Unbounded traversal is forbidden.

## Path-state precedence

Recommended:

```text
NOT_TESTED
>
INFERRED
>
PROVEN
```

`PROVEN` means every edge is `OBSERVED` or `STATICALLY_PROVEN`.

## Deterministic impact factors

```text
cross_tenant
uses_privileged_credential
reaches_sensitive_resource
contains_destructive_capability
contains_failed_security_property
contains_authorization_mutation
```

No speculative exploitability score in MVP.

## Property mapping registry

Example:

```yaml
MCP.AUTHZ.PER_OPERATION:
  graph_effects:
    - CAN_INVOKE
    - AUTHORIZED_BY

MCP.IDENTITY.CONFUSED_DEPUTY:
  graph_effects:
    - authority_mismatch
```

Use actual registry IDs from `main`.

## Redaction

Reuse Cycle 001 redaction.

Credentials use logical identities only:

```text
node:credential:crm-service-token
```

Never include credential material in labels.

## Rendering

Canonical JSON -> Mermaid/DOT.

Renderer requirements:

- escape labels;
- cap label length;
- do not embed raw source snippets;
- include edge evidence-state labels;
- preserve stable IDs in metadata where practical.

## Synthetic fixture contract

```text
known topology
+
known authority
+
known evidence states
=
known graph
+
known paths
```

## Benchmark integration

`BenchmarkRecord` is optional input.

Graph generation must work for a single local assessment without Cycle 007 corpus context.

## CI

Minimum regression assertions:

```text
same facts -> same graph digest
same graph -> same path set
observed edge without evidence -> invalid
inferred edge without rationale -> invalid
invalid node reference -> invalid
unbounded traversal -> prevented
secret-bearing label -> redacted/rejected
```

## Future compatibility

Cycle 009 should be able to consume:

```text
path_id
nodes
edges
security properties
evidence state
impact factors
preconditions
```

Cycle 008 must not execute those paths.
