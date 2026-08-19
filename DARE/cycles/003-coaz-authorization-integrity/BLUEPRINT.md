# Cycle 003 — Blueprint: COAZ-MCP Authorization-to-Execution Integrity

> Status: **approved*
> Issue: #4
> Depends on: approved Cycle 003 `DESIGN.md`, Cycle 001, Cycle 002

## 1. Architecture goal

Add a deterministic authorization-integrity harness that can prove whether a PEP reused a permit after the MCP operation changed semantically between authorization and forwarding.

```text
                       Vector Definition
                              |
                              v
                     Integrity Runner
                              |
              +---------------+---------------+
              |                               |
              v                               v
       MCP Operation                    Trusted Context
              |                               |
              +---------------+---------------+
                              |
                              v
                  AuthorizationProjector
                              |
                    AuthorizationProjection
                              |
                              v
                     Binding Engine
                              |
                  authorized_binding=A
                              |
                              v
                    Decision Provider
                          PERMIT
                              |
                              v
                      Mutation Stage
                              |
                              v
                  final MCP operation
                              |
                              v
                  AuthorizationProjector
                              |
                              v
                     Binding Engine
                              |
                    final_binding=B
                              |
                 +------------+------------+
                 |                         |
               A==B                       A!=B
                 |                         |
                 v                         v
       reuse current permit          re-evaluate/refuse
                 |                         |
                 +------------+------------+
                              |
                              v
                    Synthetic Exec Sink
                              |
                              v
                      Vector Result
                              |
                              v
                  SecurityEvidence v1
```

## 2. Workspace changes

Planned layout; task-001 MUST reconcile actual Cycle 002 merged names before creating duplicates:

```text
crates/
  dare-security-evidence/            # existing Cycle 001
  dare-mcp-discovery/                # expected Cycle 002 library or actual merged equivalent
  dare-coaz-integrity/               # new Cycle 003 library
  dare-agent-security-cli/           # expected Cycle 002 CLI or actual merged equivalent

schemas/
  vectors/coaz-integrity/v1/
    vector.schema.json
    result.schema.json

vectors/
  coaz-mcp/authorization-integrity/v1/
    COAZ-INTEGRITY-001.json
    COAZ-INTEGRITY-002.json
    COAZ-INTEGRITY-003.json
    COAZ-INTEGRITY-004.json
    COAZ-INTEGRITY-005.json
    COAZ-INTEGRITY-006.json
    COAZ-INTEGRITY-007.json

examples/
  coaz-integrity/
    secure/
    vulnerable/

labs/
  synthetic-mcp/                     # extend, do not fork

DARE/cycles/003-coaz-authorization-integrity/
  DESIGN.md
  BLUEPRINT.md
  TASKS.md
  dare-dag.yaml
  dag-graph.mmd
  EXECUTION/
```

## 3. Dependency direction

Required direction:

```text
dare-agent-security-cli
          |
          v
  dare-coaz-integrity
      /          \
     v            v
Cycle 002 MCP   dare-security-evidence
contracts       (Cycle 001)
```

Cycle 001 evidence MUST remain independent of MCP, AuthZEN and COAZ.

Cycle 002 discovery/domain code MUST NOT depend on Cycle 003.

## 4. Standards snapshot

Create a source metadata structure used by every vector:

```rust
pub struct StandardReference {
    pub family: String,
    pub document: String,
    pub version: String,
    pub status: StandardStatus,
    pub section: Option<String>,
    pub upstream_issue: Option<String>,
}
```

Required references include:

```text
OpenID AuthZEN Authorization API 1.0
COAZ Framework 1.0 Draft 1
COAZ-MCP Binding 1.0 Draft 1
COAZ-MCP §9 PEP Behavior
COAZ-MCP §11.5 Mapping Integrity
openid/authzen#603 (OPEN proposal at design time)
MCP 2026-07-28 tools/call semantics
```

Vector results MUST preserve the distinction between normative document references and open issue/proposal references.

## 5. Core domain types

```rust
pub struct McpOperation {
    pub method: String,
    pub params: CanonicalValue,
}

pub struct TrustedAuthorizationContext {
    pub subject_id: String,
    pub agent_id: Option<String>,
    pub claims: CanonicalValue,
}

pub struct MappingIdentity {
    pub kind: MappingKind,
    pub id: String,
    pub revision: Option<String>,
    pub digest: String,
}

pub struct AuthorizationProjection {
    pub mapping: MappingIdentity,
    pub mapped_inputs: CanonicalValue,
    pub trusted_inputs: CanonicalValue,
    pub authzen_request: CanonicalValue,
}

pub struct AuthorizationBinding {
    pub algorithm: String,
    pub digest: String,
}
```

`CanonicalValue` is a project-owned normalized JSON-like domain representation. Public contracts MUST NOT expose third-party SDK runtime types.

## 6. Canonicalization

Canonicalization has two stages:

```text
raw fixture/domain value
        |
        v
semantic normalization
        |
        v
deterministic canonical serialization
        |
        v
SHA-256 digest
```

Requirements:

- sort object keys deterministically;
- preserve array order;
- normalize typed numeric/string/bool/null semantics consistently;
- reject non-finite numeric values;
- avoid raw transport bytes as the equality boundary;
- use the same implementation for authorized and final projections;
- fixtures include expected canonical forms/digests where stable.

An RFC 8785-compatible final encoding MAY be used if it fits the merged Rust baseline; the implementation MUST own the semantic normalization contract regardless of library choice.

## 7. Binding material

The binding digest is computed over a versioned object:

```rust
pub struct BindingMaterialV1 {
    pub binding_version: String,
    pub method: String,
    pub operation_name: Option<String>,
    pub mapping_identity: MappingIdentity,
    pub mapped_inputs: CanonicalValue,
    pub trusted_inputs: CanonicalValue,
    pub authzen_request_digest: String,
}
```

Why include mapping identity even when two mappings construct the same AuthZEN request: a permit must not silently migrate across a mapping-selection change whose semantics merely happen to collide in one fixture.

## 8. Authorization projector

```rust
pub trait AuthorizationProjector: Send + Sync {
    fn project(
        &self,
        operation: &McpOperation,
        trusted: &TrustedAuthorizationContext,
    ) -> Result<AuthorizationProjection, ProjectionError>;
}
```

Reference implementations for Cycle 003:

```text
DefaultToolsCallProjector
DeclaredRentalQuoteProjector
```

`DeclaredRentalQuoteProjector` must model a declared mapping where `daily_rate`, `customer_id` and agent/user context are mapping-relevant.

Full arbitrary CEL evaluation is deliberately deferred.

## 9. Decision provider

```rust
pub trait DecisionProvider: Send + Sync {
    fn evaluate(
        &self,
        projection: &AuthorizationProjection,
        binding: &AuthorizationBinding,
    ) -> Result<AuthorizationDecision, DecisionError>;
}
```

Reference `DeterministicPdp` reads fixture policy only.

```rust
pub struct AuthorizationDecision {
    pub decision_id: String,
    pub decision: Decision,
    pub bound_to: AuthorizationBinding,
}
```

`AuthorizationDecision` is an internal test artifact, not an OAuth token and not a cryptographic capability.

## 10. Enforcement modes

```rust
pub enum ReferencePepMode {
    SecureReevaluate,
    SecureRefuseOnChange,
    VulnerableReusePermit,
}
```

### SecureReevaluate

If `final_binding != authorized_binding`, project/evaluate the final operation again. Forward only if the new decision permits it.

### SecureRefuseOnChange

If bindings differ, refuse without forwarding.

### VulnerableReusePermit

Intentionally reuse the original permit. This mode exists only in the local synthetic harness and MUST be impossible to select for a non-synthetic target.

## 11. Mutation stage

```rust
pub trait OperationMutator {
    fn mutate(
        &self,
        operation: &McpOperation,
        trusted: &TrustedAuthorizationContext,
    ) -> Result<MutationResult, MutationError>;
}
```

`MutationResult` may change operation and/or trusted context.

Supported deterministic mutation kinds:

```text
NONE
TOOL_NAME
MAPPED_ARGUMENT
METHOD
MAPPED_TRUSTED_CONTEXT
JSON_REORDER_ONLY
UNMAPPED_FIELD
```

## 12. Synthetic policy

The default vector policy must make stale-permit failures observable.

Example:

```text
rental.quote daily_rate <= 1000 -> PERMIT
rental.quote daily_rate > 1000  -> DENY
rental.quote_internal            -> DENY for standard subject
```

Thus vector 003 can prove:

```text
initial daily_rate=50      -> PERMIT(A)
mutation daily_rate=5000   -> final binding B
secure re-evaluation       -> DENY(B), no forward
vulnerable stale permit    -> forward under PERMIT(A), FAIL
```

No external business action is executed.

## 13. Execution sink

```rust
pub trait ExecutionSink {
    fn forward(&mut self, operation: &McpOperation) -> Result<SinkReceipt, SinkError>;
}
```

`SyntheticExecutionSink` records:

```text
operation method
operation name
sanitized params/digest
binding used for authorization
decision id
forwarded timestamp/sequence
```

The sink MUST remain in-process/local and non-destructive.

## 14. Vector definition schema

`vector.schema.json` represents reusable test intent:

```text
schema_version
vector_id
title
standards
initial_operation
trusted_context
projector_fixture
pdp_fixture
mutation
expected
safety
```

Expected enforcement enum:

```text
FORWARD_WITH_EXISTING_PERMIT
REEVALUATE_OR_REFUSE
PERMIT_REMAINS_BOUND
```

## 15. Vector result schema

`result.schema.json` records execution:

```text
schema_version
vector_id
standards
initial_operation
initial_projection
initial_binding
initial_decision
mutation
final_operation
final_projection
final_binding
enforcement_trace
sink_receipt
expected
observed
verdict
redaction
started_at
finished_at
```

No raw access token field exists.

## 16. Observed enforcement enum

```text
FORWARDED_WITH_EXISTING_PERMIT
FORWARDED_AFTER_REEVALUATION
REFUSED_AFTER_BINDING_CHANGE
DENIED_AFTER_REEVALUATION
FORWARDED_WITH_STALE_PERMIT
NO_FORWARD_INITIAL_DENY
INCONCLUSIVE_PROJECTION
HARNESS_ERROR
```

Verdict logic is pure and table-driven.

## 17. Vector semantics

### COAZ-INTEGRITY-001

No mutation. Binding remains equal. Existing permit may forward.

### COAZ-INTEGRITY-002

Change `params.name` after permit. Mapping identity/operation name changes. Existing permit cannot be reused.

### COAZ-INTEGRITY-003

Declared projection consumes `daily_rate`. Mutate `50 -> 5000`. Binding must change.

### COAZ-INTEGRITY-004

Change JSON-RPC method after permit. Binding must change even if resulting projection coincidentally resembles the original.

### COAZ-INTEGRITY-005

Change a mapped trusted value, for example synthetic `agent_id`. Binding must change.

### COAZ-INTEGRITY-006

Reorder JSON keys / alter formatting only. Semantic normalization remains identical; binding remains equal.

### COAZ-INTEGRITY-007

Change a field intentionally excluded by the selected mapping. Mapping selection, mapped values and authorization request remain identical; binding remains equal.

## 18. Evidence bridge

`dare-coaz-integrity` depends on `dare-security-evidence` and emits one evidence record per vector result.

Suggested vector IDs in evidence are identical to the portable vector IDs.

Evidence metadata references:

```text
result artifact path
digest
standards references
reference PEP mode
```

The evidence crate itself receives no COAZ-specific schema changes.

## 19. CLI contract

Preferred shape, subject to task-001 reconciliation with merged Cycle 002 CLI:

```bash
dare-agent-security validate coaz-integrity --all
dare-agent-security validate coaz-integrity --fixture COAZ-INTEGRITY-003
dare-agent-security validate coaz-integrity --all --json
dare-agent-security validate coaz-integrity --all --reference-mode vulnerable
```

Safety rules:

- `vulnerable` reference mode only works with built-in synthetic fixtures;
- no URL/stdio arbitrary target parameter for this cycle;
- `--json` emits result JSON only to stdout;
- diagnostics go to stderr;
- evidence output uses an explicit output directory;
- stable non-zero exit for vector FAIL and harness ERROR, exact mapping documented before release.

## 20. Tests

### Unit

- canonicalization equivalence/inequality;
- mapping identity digest;
- binding material digest;
- projector behavior;
- decision provider;
- mutation operations;
- verdict truth table;
- redaction.

### Contract

- vector definition schema;
- result schema;
- semantic validation;
- unsupported major fail closed;
- PASS/FAIL fixture round-trip.

### Integration

- default mapping identity vector;
- declared mapped-argument vector;
- trusted-context vector;
- secure re-evaluate mode;
- secure refuse mode;
- vulnerable stale-permit mode;
- evidence bridge.

### E2E proof

For mutation vectors 002–005, vulnerable mode MUST prove:

```text
initial_decision = PERMIT
initial_binding != final_binding
sink.forwarded = true
observed = FORWARDED_WITH_STALE_PERMIT
verdict = FAIL
```

Secure modes MUST never produce that trace.

For controls 006–007:

```text
initial_binding == final_binding
```

## 21. CI gates

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Additional gates:

- validate vector definitions offline;
- validate result fixtures offline;
- scan fixtures for secret canaries;
- run all seven vectors in secure mode;
- run expected vulnerable FAIL matrix;
- assert no external network access from Cycle 003 test harness;
- assert current standards metadata fixture is present.

## 22. Documentation

Deliver:

```text
docs/coaz-integrity.md
```

or repository-equivalent docs covering:

- the authorization-to-execution integrity problem;
- difference between current COAZ-MCP normative text and issue #603 proposal;
- why semantic equality is not byte equality;
- secure and vulnerable traces;
- how to run vectors;
- how to consume result/evidence JSON;
- upstream contribution workflow and IPR reminder.

## 23. Upstream contribution package

Task 012 should produce a small neutral package suitable for discussion upstream:

```text
vector definitions
expected semantics
reference traces
no DARE-private/customer data
```

Do not open or modify an upstream PR automatically. Human review is required before any standards contribution.

## 24. Definition of architecture complete

Architecture is ready for execution when these invariants are accepted:

- permit binding is semantic and versioned;
- only mapping-relevant semantics invalidate the permit;
- mapping identity is part of the binding;
- secure reference behavior re-evaluates or refuses on binding change;
- vulnerable mode is synthetic-only;
- vector/result contracts are separate from generic evidence;
- Cycle 001 evidence remains standards-agnostic;
- full COAZ/CEL implementation is not required;
- all tests are deterministic, local and non-destructive;
- standards draft/open-issue status is preserved accurately.
