# Cycle 001 — Blueprint: Deterministic Security Evidence Schema

> Status: **ARCHITECTURE PROPOSED**
> Depends on: `DESIGN.md` (approved)
> Issue: #2

## 1. Architecture goal

Implement a small, reusable Rust evidence kernel that exposes a stable, versioned, machine-readable security evidence contract without coupling the OSS project to a CLI, database, SaaS control plane, or customer-specific model.

The architecture must support this future flow:

```text
Discovery / Vector / Runtime / CI
              |
              v
      Rust Evidence Model
              |
      +-------+--------+
      |                |
      v                v
 JSON serialization   JSON Schema
      |                |
      +-------+--------+
              v
       Validation Gate
              |
              v
     Evidence Artifact
```

## 2. Technology decisions

### 2.1 Language

Rust is the canonical implementation language.

### 2.2 Serialization

Use `serde` + `serde_json`.

### 2.3 Schema

Use JSON Schema as the external validation contract.

The schema file is committed as a versioned artifact rather than generated only at runtime.

### 2.4 IDs and timestamps

Use stable string identifiers in the public contract.

Recommended implementation dependencies:

- `uuid` for evidence record identifiers;
- `time` or `chrono` for RFC 3339 timestamps.

The implementation should prefer the smallest dependency surface compatible with correctness and maintenance.

### 2.5 Hash metadata

Cycle 001 stores algorithm + digest metadata only.

Example:

```json
{
  "algorithm": "sha256",
  "value": "..."
}
```

No signing infrastructure is implemented in this cycle.

## 3. Workspace layout

Target repository layout after this cycle:

```text
.
├── Cargo.toml
├── crates/
│   └── dare-security-evidence/
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── model.rs
│           ├── verdict.rs
│           ├── version.rs
│           ├── validation.rs
│           └── redaction.rs
├── schemas/
│   └── evidence/
│       └── v1/
│           └── evidence.schema.json
├── examples/
│   └── evidence/
│       ├── pass.json
│       ├── fail.json
│       ├── inconclusive.json
│       └── error.json
└── DARE/
    └── cycles/
        └── 001-evidence-schema/
            ├── DESIGN.md
            ├── BLUEPRINT.md
            ├── TASKS.md
            ├── dare-dag.yaml
            └── dag-graph.mmd
```

`TASKS.md` and the DAG are produced only after human review of this blueprint.

## 4. Crate boundary

Create one reusable library crate:

```text
dare-security-evidence
```

Responsibilities:

- canonical Rust model;
- serialization/deserialization;
- semantic version parsing;
- verdict types;
- record validation beyond JSON structural validation;
- redaction utilities required by the public evidence contract;
- fixture validation helpers where appropriate.

Explicit non-responsibilities:

- MCP transport;
- HTTP client;
- AuthZEN client;
- attack execution;
- graph traversal;
- database persistence;
- CLI UX;
- customer integration.

This boundary is deliberate so all future crates can depend inward on evidence.

## 5. Core public model

Proposed top-level Rust shape:

```rust
pub struct SecurityEvidence {
    pub schema: SchemaRef,
    pub id: String,
    pub vector: VectorRef,
    pub target: TargetRef,
    pub preconditions: Vec<Precondition>,
    pub operation: Option<NormalizedOperation>,
    pub authorization_context: Option<AuthorizationContext>,
    pub expected: ExpectedOutcome,
    pub observed: ObservedOutcome,
    pub verdict: Verdict,
    pub severity: Option<SeverityAssessment>,
    pub standards: Vec<StandardMapping>,
    pub artifacts: Vec<EvidenceArtifactRef>,
    pub hashes: Vec<HashRef>,
    pub redaction: RedactionMetadata,
    pub timestamps: EvidenceTimestamps,
}
```

Exact naming may be adjusted during implementation only if semantics stay identical to the approved Design.

## 6. Component contracts

### 6.1 `SchemaRef`

Fields:

```text
id
version
```

Example:

```json
{
  "id": "https://darelabs.tech/schemas/evidence",
  "version": "1.0.0"
}
```

Requirement:

- unsupported major versions are rejected.

### 6.2 `VectorRef`

Fields:

```text
id
version
name? 
```

Example:

```json
{
  "id": "COAZ-MCP-PERMIT-INTEGRITY-001",
  "version": "1.0.0"
}
```

### 6.3 `TargetRef`

Fields:

```text
type
id
name?
software?
software_version?
protocol?
protocol_version?
```

`target.id` must be an operator-safe identifier and must not require embedding a secret URL or credential.

### 6.4 Preconditions

Represent conditions required to interpret the vector.

Minimal shape:

```text
id?
description
satisfied
```

Avoid embedding executable scripts in the public evidence record.

### 6.5 `NormalizedOperation`

The evidence format needs a protocol-neutral operation representation.

Initial generic shape:

```text
kind
name
resource?
arguments_digest?
attributes?
```

Important design decision:

Cycle 001 must **not** encode MCP-specific fields as top-level schema requirements. MCP-specific normalization belongs to future MCP crates.

### 6.6 Authorization context

This is metadata for interpreting a security decision, not a credential container.

Proposed shape:

```text
principal_id?
agent_id?
authn_method?
policy_id?
policy_version?
context_attributes?
```

Raw bearer tokens, secrets, passwords and private keys are forbidden.

### 6.7 Expected outcome

Generic shape:

```text
decision?
result?
description?
```

Known decision vocabulary should initially support common authorization outcomes without claiming to be a PDP standard:

```text
ALLOW
DENY
RE_EVALUATE
REQUIRES_APPROVAL
NOT_APPLICABLE
```

The schema may allow an explicit namespaced extension string for future protocols, but extensions must not weaken deterministic comparison semantics.

### 6.8 Observed outcome

Generic shape:

```text
decision?
result?
description?
source
```

`source` identifies where the observation came from, for example:

```text
protocol_response
policy_engine
runtime_event
fixture
```

An LLM-generated narrative cannot be the sole source for a deterministic vector.

### 6.9 Verdict

Rust enum:

```rust
pub enum Verdict {
    Pass,
    Fail,
    Inconclusive,
    Error,
}
```

Wire format:

```text
PASS
FAIL
INCONCLUSIVE
ERROR
```

No implicit default.

### 6.10 Severity

Optional because conformance failures are not always vulnerabilities.

Proposed shape:

```text
level
rationale
```

Initial levels:

```text
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

Severity must not be inferred solely from the verdict.

### 6.11 Standards mappings

Shape:

```text
organization
standard
version?
control
url?
```

Examples:

```text
OpenID / AuthZEN / draft-version / section
OWASP / Agentic Security / 2026 / ASIxx
IETF / OAuth / RFC-or-draft / section
```

A mapping is attribution, not endorsement.

### 6.12 Evidence artifacts

Artifact references should not inline arbitrary blobs.

Shape:

```text
type
uri_or_path
digest?
media_type?
redacted
```

Cycle 001 validates metadata only; artifact storage is out of scope.

### 6.13 Redaction metadata

Required top-level object.

Shape:

```text
applied
strategy
fields
```

Potential strategies:

```text
NONE_REQUIRED
REMOVE
MASK
HASH
TOKENIZE
MIXED
```

`NONE_REQUIRED` means the producer verified that no sensitive value required redaction. It must not mean redaction was skipped.

### 6.14 Timestamps

Fields:

```text
started_at?
observed_at
recorded_at
```

RFC 3339 UTC is the canonical wire representation.

## 7. Structural vs semantic validation

Use two validation layers.

### Layer A — JSON Schema

Checks:

- required fields;
- types;
- enum values;
- formats;
- basic pattern constraints;
- unknown-field policy.

### Layer B — Rust semantic validation

Checks invariants that JSON Schema alone should not own.

Examples:

- supported schema major version;
- `PASS` requires expected and observed outcomes that compare successfully;
- `FAIL` requires a deterministic mismatch;
- `INCONCLUSIVE` cannot claim deterministic equality or mismatch;
- `ERROR` must include an execution/validation error description;
- raw secret-like fields are rejected where detectable;
- redaction metadata is internally coherent;
- evidence timestamps are logically ordered when all are present.

## 8. Deterministic comparison strategy

Do not define universal semantic comparison for every future protocol in Cycle 001.

Instead, define a small generic comparison mechanism:

```text
ExpectedOutcome
ObservedOutcome
        |
        v
OutcomeComparator trait
        |
        v
Verdict derivation
```

Possible Rust abstraction:

```rust
pub trait OutcomeComparator {
    fn compare(
        &self,
        expected: &ExpectedOutcome,
        observed: &ObservedOutcome,
    ) -> ComparisonResult;
}
```

Cycle 001 should ship a default exact comparator for generic fields only.

Protocol-specific comparators, such as COAZ-MCP semantic operation integrity, belong to future vector/MCP crates.

## 9. Verdict derivation

Preferred architecture:

```text
vector execution
      |
      v
expected + observed
      |
      v
comparator
      |
      v
ComparisonResult
      |
      v
Verdict
```

Avoid allowing callers to create contradictory records such as:

```text
expected = DENY
observed = ALLOW
verdict = PASS
```

Implementation direction:

- builder/factory derives verdict when deterministic comparison is available;
- raw deserialization still validates consistency before the record is considered valid.

## 10. Secret-safety design

Cycle 001 cannot guarantee perfect secret detection, but it can enforce strong contract-level controls.

### Required protections

1. No field named or intended for raw credentials.
2. Authorization context accepts identifiers/metadata only.
3. Redaction metadata is mandatory.
4. Validation scans configurable map keys for high-risk names such as:
   - `password`;
   - `secret`;
   - `token`;
   - `api_key`;
   - `private_key`;
   - `authorization`.
5. Tests prove that representative raw-secret payloads are rejected or redacted before serialization.

Important:

Heuristics are defense-in-depth, not a claim that all secrets can be identified automatically.

## 11. Unknown fields and extensibility

For v1, prefer strict top-level objects using JSON Schema `additionalProperties: false` where feasible.

Extension points should be deliberate and namespaced rather than allowing arbitrary fields everywhere.

Example future extension container:

```json
{
  "extensions": {
    "org.example.mcp": {}
  }
}
```

Cycle 001 may define the container but does not need to use it.

## 12. JSON Schema publication strategy

Canonical path:

```text
schemas/evidence/v1/evidence.schema.json
```

Recommended `$id`:

```text
https://darelabs.tech/schemas/evidence/v1/evidence.schema.json
```

The repository copy is normative for a tagged release.

Future documentation hosting may serve the same schema URL, but the build must not depend on a network fetch.

## 13. Fixture strategy

Public fixtures:

```text
examples/evidence/pass.json
examples/evidence/fail.json
examples/evidence/inconclusive.json
examples/evidence/error.json
```

All fixtures use a synthetic target, for example:

```text
synthetic-payment-mcp
```

No customer-derived identifiers.

Also create invalid test fixtures under the crate tests, not necessarily in the public examples directory.

Candidate invalid cases:

- unsupported major version;
- missing vector id;
- contradictory PASS;
- ERROR without error context;
- invalid timestamp ordering;
- secret-like raw authorization field;
- invalid verdict enum;
- malformed digest.

## 14. Test architecture

### Unit tests

Cover:

- enum wire formats;
- version parsing;
- semantic validation;
- redaction helpers;
- comparator behavior;
- verdict derivation.

### Contract tests

For every public fixture:

1. deserialize;
2. validate JSON Schema;
3. validate semantic invariants;
4. re-serialize;
5. deserialize again;
6. assert semantic equality.

### Negative tests

Each invalid fixture must fail for a documented reason.

## 15. CI gates

Cycle 001 implementation PR must pass:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Additionally:

```text
JSON Schema self-validation
all public fixtures validate structurally
all public fixtures validate semantically
all invalid fixtures fail as expected
no committed secrets detected by the repository's security checks
```

A lightweight GitHub Actions workflow may be added if the repository does not yet have Rust CI, but building the future full `dare-agent-security` GitHub Action is outside this cycle.

## 16. Error model

The library should expose typed errors rather than strings as its primary API.

Proposed classes:

```text
UnsupportedSchemaVersion
StructuralValidationError
SemanticValidationError
VerdictConsistencyError
RedactionViolation
SerializationError
```

Errors must be safe to display and must not echo secrets from rejected values.

## 17. Dependency direction

Required dependency rule:

```text
dare-security-evidence
        ^
        |
 future cli / mcp / vectors / graph
```

The evidence crate must not depend on future domain crates.

This is an architectural invariant.

## 18. Public API stability

The project is pre-alpha, but the evidence schema itself needs explicit compatibility discipline.

Rules:

- Rust API may evolve before 1.0;
- serialized v1 evidence semantics must follow the Design versioning rules;
- breaking wire-format changes require a new schema major version;
- fixture files are compatibility tests once released.

## 19. Security review checklist

Before implementation approval is complete, verify:

- [ ] No raw credential field exists.
- [ ] Redaction metadata is required.
- [ ] Verdict contradiction is impossible after validation.
- [ ] Unknown major schema versions fail closed.
- [ ] Protocol-specific assumptions have not leaked into the generic core.
- [ ] Customer-specific concepts are absent.
- [ ] Error messages cannot expose rejected secret values.
- [ ] The crate has no network dependency at validation time.
- [ ] JSON Schema can validate independently from Rust.

## 20. Implementation boundaries for TASKS phase

Once this Blueprint is approved, `TASKS.md` should decompose implementation roughly into:

```text
T001 workspace + evidence crate bootstrap
T002 core types and wire enums
T003 JSON Schema v1
T004 semantic validation/versioning
T005 redaction safety
T006 outcome comparison + verdict consistency
T007 public fixtures
T008 contract/negative tests
T009 CI gates + documentation
T010 final cycle verification
```

These are architectural work packages only. Final task definitions and dependencies belong to the next DARE phase.

## 21. Definition of architecture complete

The Blueprint is considered approved when the human reviewer accepts:

- Rust as the evidence kernel implementation;
- one isolated evidence crate;
- JSON + JSON Schema as the wire contract;
- four-verdict model;
- structural + semantic validation layers;
- verdict consistency rules;
- mandatory redaction metadata;
- strict generic/protocol-specific separation;
- v1 compatibility rules;
- the proposed repository layout and dependency direction.
