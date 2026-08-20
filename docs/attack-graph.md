# Agent Attack Graph MVP

Cycle 008 converts normalized facts from the existing inventory, authorization-integrity, evidence, coverage, and optional benchmark contracts into a deterministic relationship graph. It does not create a second evidence, verdict, coverage, property, or benchmark engine.

## Taxonomy

Nodes represent humans, agents, identities, delegated authority, MCP servers, capabilities, tools, logical credentials, downstream services, resources, data, tenants, and policy decision/enforcement points. Semantic edges represent authentication, delegation, invocation, calls, credential use, authorization/enforcement, data operations, tenancy, trust-boundary crossing, and reachability.

Credential nodes and authority fields contain logical IDs such as `node:credential:crm-service-token`, never credential material.

## Evidence semantics

- `OBSERVED`: runtime evidence directly demonstrates the edge; `evidence_ids` are required.
- `STATICALLY_PROVEN`: deterministic source/configuration evidence proves the edge; `evidence_ids` are required.
- `INFERRED`: plausible but unproven; rationale and source facts are required.
- `NOT_TESTED`: identified but unevaluated; a reason is required.

These states are not PASS/FAIL verdicts. Existing Cycle 001/006 verdict and coverage values are only preserved as security context.

## Paths and impact factors

Traversal requires nonzero `max_depth` and `max_paths`, detects cycles, and has hard upper safety bounds. Path state follows the weakest edge: `NOT_TESTED`, then `INFERRED`, otherwise `PROVEN`. `PROVEN` describes evidence strength, not exploitability.

Paths annotate deterministic booleans for cross-tenant access, privileged credential use, sensitive resources, destructive capabilities, failed security properties, and authorization mutation. The MVP intentionally has no speculative risk score.

## Determinism and outputs

Node and edge ordering is stable. Edge IDs digest source, semantic type, target, and normalized authority. Graph/path IDs use key-sorted canonical JSON and SHA-256. `attack-graph.json` is canonical; Mermaid and DOT are escaped derived views.

```bash
cargo run -p dare-agent-security -- validate attack-graph \
  --facts fixtures/attack-graph/safe-read.json \
  --output-dir .dare-agent-security/attack-graph
```

## Limitations and safety

Input is a normalized fact file; automatic adapters for every historical artifact remain future work. Completeness cannot exceed inventory and assessment coverage. The command performs offline analysis only: it never invokes tools, follows arbitrary URIs, executes exploit chains, or performs state-changing validation.
