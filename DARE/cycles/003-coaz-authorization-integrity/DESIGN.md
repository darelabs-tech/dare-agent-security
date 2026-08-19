# Cycle 003 — Design: COAZ-MCP Authorization-to-Execution Integrity

> Status: **approved**
> Issue: #4
> Baseline: Cycle 001 evidence kernel + Cycle 002 MCP discovery/synthetic lab
> Upstream focus: OpenID AuthZEN issue #603

## 1. Problem

An authorization decision is only meaningful for the operation that produced that decision.

A PEP can correctly map an MCP request into an AuthZEN request, receive `permit`, and still violate the security boundary if middleware changes mapping-relevant semantics before forwarding or executing the MCP operation.

```text
MCP tools/call
  name = rental.quote
  daily_rate = 50
        |
        v
COAZ mapping
        |
        v
AuthZEN evaluation
        |
        v
PERMIT
        |
        v
post-decision mutation
  daily_rate = 5000
        |
        v
forward using stale permit   <-- integrity failure
```

Cycle 003 builds deterministic conformance vectors for this authorization-to-use boundary.

## 2. Security property

A permit is bound to the final normalized operation that was authorized.

If an input that either:

1. selects the applicable mapping, or
2. contributes to the constructed authorization request

changes semantically after authorization, the earlier permit MUST NOT be reused by the DARE reference enforcement model. The final operation must be re-evaluated or refused.

This cycle treats that statement as the security property under test derived from upstream AuthZEN issue #603. It MUST NOT misrepresent the proposal as already-normative COAZ-MCP text while the upstream issue remains unresolved.

## 3. Standards baseline

Cycle 003 references:

- OpenID AuthZEN Authorization API 1.0;
- COAZ Framework 1.0 Draft 1;
- COAZ-MCP Binding 1.0 Draft 1;
- OpenID AuthZEN issue #603, `[COAZ-MCP] Bind a permit to the MCP operation actually forwarded`;
- MCP `2026-07-28` for the current MCP request shape used by the repository.

The implementation MUST record standards/profile identifiers in vector metadata and MUST make draft/upstream status explicit.

The current COAZ-MCP draft defines PEP mapping/evaluation/enforcement behavior and a Mapping Integrity security consideration, but issue #603 proposes an additional authorization-to-execution binding clarification. Cycle 003 tests that proposed property without claiming OpenID endorsement.

The draft COAZ-MCP text and MCP `2026-07-28` are not perfectly version-aligned in lifecycle examples. Cycle 003 therefore scopes executable conformance to `tools/call` and records the exact standards snapshots used; it does not treat legacy lifecycle examples as authoritative for current MCP transport behavior.

## 4. Dependencies

Hard dependencies:

```text
Cycle 001
  SecurityEvidence v1

Cycle 002
  MCP request/domain adapter
  synthetic MCP lab
  safe redaction primitives where reusable
  CLI foundation
```

Cycle 003 MUST build on the merged public contracts rather than duplicate them.

## 5. Scope

### In scope

- deterministic normalized operation identity;
- deterministic authorization projection identity;
- pre-authorization snapshot;
- controlled post-permit mutation stage;
- final-operation recomputation before forwarding;
- re-evaluate/refuse behavior when mapped semantics changed;
- all five upstream candidate vectors;
- positive semantic controls proving harmless serialization changes do not invalidate a permit;
- declared-mapping fixture where a tool argument contributes to authorization;
- default-mapping fixture where method/tool identity contributes to authorization;
- trusted-context fixture using synthetic validated claims/context;
- PASS and intentionally vulnerable FAIL reference implementations/fixtures;
- machine-readable vector definitions and result artifacts;
- bridge to Cycle 001 `SecurityEvidence`;
- CLI execution against synthetic fixtures;
- non-destructive synthetic MCP operations only.

### Out of scope

- full COAZ-MCP conformance implementation;
- general CEL conformance or arbitrary CEL execution;
- production AuthZEN PDP deployment;
- OAuth login/token acquisition;
- authorization bypass testing against third-party systems;
- real payment or destructive tools;
- obligations/AARP semantics;
- post-action cryptographic receipts;
- agent attack graph;
- enterprise control plane;
- network-wide target discovery;
- claiming upstream issue #603 has been accepted before it actually is.

## 6. Vector set

Required vectors:

```text
COAZ-INTEGRITY-001
unchanged tools/call after permit
EXPECTED: FORWARD_WITH_EXISTING_PERMIT

COAZ-INTEGRITY-002
mapped tool name changed after permit
EXPECTED: REEVALUATE_OR_REFUSE

COAZ-INTEGRITY-003
mapped argument changed after permit
EXPECTED: REEVALUATE_OR_REFUSE

COAZ-INTEGRITY-004
MCP method changed after permit
EXPECTED: REEVALUATE_OR_REFUSE

COAZ-INTEGRITY-005
mapped trusted context changed after permit
EXPECTED: REEVALUATE_OR_REFUSE
```

Semantic control vectors:

```text
COAZ-INTEGRITY-006
JSON object key order / formatting changes only
EXPECTED: PERMIT_REMAINS_BOUND

COAZ-INTEGRITY-007
field excluded by the selected mapping changes while mapping selection and mapped values remain unchanged
EXPECTED: PERMIT_REMAINS_BOUND
```

The controls ensure the implementation tests semantic binding rather than raw byte equality.

## 7. Normalized authorization operation

Cycle 003 introduces a project-owned normalized representation. It MUST NOT expose an AuthZEN SDK, MCP SDK, or CEL runtime type as its public contract.

Conceptually:

```rust
pub struct NormalizedAuthorizationOperation {
    pub method: String,
    pub operation_name: Option<String>,
    pub mapping_identity: MappingIdentity,
    pub mapped_input: CanonicalValue,
    pub trusted_context: CanonicalValue,
    pub authorization_request: CanonicalValue,
}
```

The exact wire model is finalized in Blueprint.

## 8. Semantic binding

The authorization binding is derived from normalized semantics, not raw JSON bytes.

Conceptually:

```text
binding = hash(
  protocol method
  + mapping identity/revision
  + mapped input values
  + mapped trusted context
  + constructed AuthZEN request
)
```

Rules:

- JSON object key ordering must not change the binding;
- insignificant transport serialization must not change the binding;
- a mapping-selection change must change the binding;
- any value contributing to the authorization request must change the binding when its semantic value changes;
- raw access tokens and credentials must never be part of serialized public evidence;
- hash/canonicalization behavior must be deterministic and test-vectored.

## 9. Authorization projection boundary

Cycle 003 does not need a complete COAZ/CEL implementation to prove issue #603.

Introduce a project-owned abstraction:

```rust
pub trait AuthorizationProjector {
    fn project(
        &self,
        operation: &McpOperation,
        trusted_context: &TrustedAuthorizationContext,
    ) -> Result<AuthorizationProjection, ProjectionError>;
}
```

The synthetic lab provides deterministic projectors equivalent to the mappings needed by the vectors.

A future full COAZ-MCP mapping engine can implement the same interface without changing the integrity harness.

## 10. Authorization decision boundary

Reference pipeline:

```text
candidate MCP operation
        |
        v
select mapping
        |
        v
project authorization request
        |
        v
compute authorized binding
        |
        v
PDP permit/deny
        |
        v
controlled mutation hook
        |
        v
re-project final operation
        |
        v
compute final binding
        |
        +---- same ----> forward with existing permit
        |
        +---- changed --> re-evaluate OR refuse
```

A test mode that intentionally skips the final binding check is included only as a synthetic vulnerable reference to prove that the vectors produce FAIL evidence.

## 11. Deterministic PDP

Use a local deterministic PDP test double by default.

It must:

- accept a sanitized AuthZEN-shaped evaluation request;
- return a deterministic permit/deny result from fixture policy;
- record request/decision metadata;
- perform no network communication;
- contain no real credentials or customer policy.

Real AuthZEN HTTP interoperability is a future capability unless it is required only as a narrowly bounded adapter test.

## 12. Synthetic domain

Reuse/extend the Cycle 002 synthetic MCP lab.

Recommended non-destructive tools:

```text
rental.quote
rental.quote_internal
vehicle.lookup
```

Example mapped arguments:

```json
{
  "customer_id": "cust-synthetic-001",
  "vehicle_id": "vehicle-synthetic-001",
  "daily_rate": 50,
  "days": 3
}
```

The tool returns synthetic quote data only. No reservation, payment, deletion, or external side effect occurs.

## 13. Mutation model

Mutations are explicit test fixtures, never arbitrary fuzzing in this cycle.

```rust
pub enum IntegrityMutation {
    None,
    ChangeToolName,
    ChangeMappedArgument,
    ChangeMethod,
    ChangeMappedTrustedContext,
    ReorderJsonObject,
    ChangeUnmappedField,
}
```

Every mutation records before/after sanitized values or digests sufficient for deterministic review.

## 14. Vector result artifact

Create a versioned artifact separate from generic Cycle 001 evidence.

Proposed path:

```text
schemas/vectors/coaz-integrity/v1/result.schema.json
```

Conceptual fields:

```text
schema_version
vector_id
standards_mapping
initial_operation
initial_projection
initial_binding
pdp_decision
mutation
final_operation
final_projection
final_binding
expected_enforcement
observed_enforcement
verdict
trace
redaction
```

No raw token, Authorization header, API key, private key, or customer data is permitted.

## 15. Evidence bridge

Each vector result produces a valid Cycle 001 `SecurityEvidence` record.

Expected/observed examples:

```text
EXPECTED: REEVALUATE_OR_REFUSE
OBSERVED: FORWARDED_WITH_STALE_PERMIT
VERDICT: FAIL
```

or:

```text
EXPECTED: REEVALUATE_OR_REFUSE
OBSERVED: REFUSED_AFTER_BINDING_CHANGE
VERDICT: PASS
```

Evidence references the vector-result artifact by stable digest/path metadata instead of extending the evidence kernel with COAZ-specific fields.

## 16. Verdict semantics

```text
PASS
observed enforcement satisfies the vector expectation

FAIL
operation reached the synthetic execution sink using a stale permit after mapping-relevant semantics changed

INCONCLUSIVE
required projection/mapping/trusted input could not be established deterministically

ERROR
harness/test infrastructure failed
```

Heuristic interpretation MUST NOT produce PASS.

## 17. Safe execution sink

The final sink is an instrumented synthetic sink that records the MCP operation it would execute.

It MUST NOT:

- call a real payment API;
- alter external state;
- access customer data;
- leave the local synthetic test boundary.

The critical FAIL condition is proven by trace:

```text
permit(binding=A)
final_binding=B
B != A
forwarded=true
```

## 18. CLI direction

Expose through the validation surface, without destabilizing `discover`:

```bash
dare-agent-security validate coaz-integrity --fixture <id>
dare-agent-security validate coaz-integrity --all
dare-agent-security validate coaz-integrity --all --json
```

Exact CLI spelling is finalized in Blueprint after reconciling the merged Cycle 002 CLI structure.

## 19. Safety invariants

- synthetic targets only by default;
- no third-party endpoint execution in Cycle 003;
- no arbitrary tool invocation;
- no destructive synthetic tool;
- no raw credentials in artifacts/logs/errors;
- no production token acquisition;
- no customer-derived fixtures;
- no uncontrolled fuzzing;
- mutation occurs only inside the instrumented local authorization-to-execution pipeline;
- upstream proposal status is represented accurately.

## 20. Test strategy

### Unit

- semantic canonicalization;
- binding equality/inequality;
- mapping identity selection;
- mutation application;
- redaction;
- expected/observed verdict calculation.

### Contract

- vector result JSON Schema;
- PASS fixtures;
- FAIL fixtures;
- unsupported major fail closed;
- round-trip semantic equality.

### Integration

- secure PEP reference path;
- intentionally vulnerable stale-permit path;
- declared mapping projection;
- default mapping projection;
- synthetic execution sink trace;
- evidence bridge.

### End-to-end

Run all required and semantic-control vectors against both secure and intentionally vulnerable reference modes where meaningful.

## 21. Acceptance criteria

Cycle 003 is complete when:

1. all five vectors from issue #4/#603 are implemented;
2. semantic-control vectors prove canonicalization is not raw-byte equality;
3. mapped argument changes are tested using a declared synthetic mapping/projection;
4. PASS and FAIL reference fixtures exist;
5. each run emits a versioned machine-readable vector result;
6. each vector can emit valid Cycle 001 evidence;
7. stale-permit forwarding is provable from the synthetic trace;
8. no raw credential or customer data is committed;
9. docs distinguish current normative COAZ-MCP text from the unresolved upstream proposal;
10. workspace format/lint/test gates pass.

## 22. Human review checklist

Approve only if all are acceptable:

- [ ] issue #603 remains the exact research target;
- [ ] Cycle 003 does not expand into a full COAZ implementation;
- [ ] semantic binding is based on mapping-relevant values, not raw JSON bytes;
- [ ] unchanged/irrelevant changes have positive control vectors;
- [ ] vulnerable reference mode is synthetic and non-destructive;
- [ ] generic evidence contract remains MCP/COAZ-agnostic;
- [ ] standards status is represented as Draft/Open Issue where applicable;
- [ ] no production or customer endpoint is in scope;
- [ ] Cycle 002 interfaces are reused rather than forked.
