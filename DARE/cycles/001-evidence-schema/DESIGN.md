# Cycle 001 — Deterministic Security Evidence Schema

> Status: **DESIGN APPROVED**
> Issue: #2
> Approved: 2026-08-18

## 1. Objective

Define the first public, versioned, machine-readable evidence contract for DARE Agent Security.

The evidence model must allow every deterministic security or conformance vector to express the chain:

```text
security property
      -> vector
      -> target
      -> normalized operation
      -> expected outcome
      -> observed outcome
      -> deterministic verdict
      -> evidence artifacts
```

The schema will become the common contract used by future discovery, validation, adversarial testing, CI, benchmarks, research datasets and enterprise ingestion.

## 2. Problem

Agentic security testing can easily degrade into subjective conclusions produced by an LLM or into unstructured logs that cannot be independently reviewed.

DARE Agent Security requires a canonical evidence record that is:

- deterministic where the security property permits deterministic evaluation;
- versioned;
- machine-validatable;
- reproducible;
- safe to serialize and share after redaction;
- independent from a specific database, UI or SaaS product;
- able to reference upstream standards without implying endorsement.

## 3. Primary use cases

### UC-001 — Vector result

Represent the result of a single security/conformance vector.

### UC-002 — CI artifact

Persist evidence as a build artifact and use the verdict as a future CI gate input.

### UC-003 — Research fixture

Publish sanitized evidence fixtures that can be independently validated and reproduced.

### UC-004 — Enterprise ingestion

Allow future private control planes to ingest the public evidence format without coupling the OSS project to an enterprise database schema.

## 4. Required information

A valid v1 evidence record must be able to represent:

- schema identifier and schema version;
- evidence record identifier;
- vector identifier and vector version;
- target type and target identifier;
- target software/protocol/specification version where known;
- preconditions;
- normalized operation or security-relevant action representation;
- policy/authorization context in a safe/redacted representation;
- expected decision/outcome;
- observed decision/outcome;
- deterministic verdict;
- severity and rationale where applicable;
- standards mappings;
- evidence artifact references;
- timestamps;
- relevant source/config/specification hashes or revisions;
- redaction metadata.

## 5. Verdict model

The initial verdict vocabulary is intentionally small:

```text
PASS
FAIL
INCONCLUSIVE
ERROR
```

Semantics:

- `PASS`: observed behavior satisfies the vector's deterministic expectation.
- `FAIL`: observed behavior violates the vector's deterministic expectation.
- `INCONCLUSIVE`: execution completed but available evidence is insufficient to decide the property deterministically.
- `ERROR`: the vector could not be evaluated because the test infrastructure, target interaction, parsing or another execution dependency failed.

`INCONCLUSIVE` and `ERROR` must never be silently converted into `PASS`.

## 6. Security properties

### SP-001 — No raw secrets required

A valid evidence record must never require a password, bearer token, API key, private key or raw credential.

### SP-002 — Explicit redaction

Sensitive source values included in evidence-generation inputs must be removed, transformed or represented through non-secret metadata before serialization.

### SP-003 — Deterministic verdict provenance

A verdict must reference the vector and the expected/observed outcomes used to derive it. LLM prose alone cannot constitute the observed outcome for a deterministic vector.

### SP-004 — Versioned semantics

The schema and vector versions must be explicit so historical evidence remains interpretable when the implementation evolves.

### SP-005 — Stable machine contract

The canonical representation must be machine-validatable independently from the Rust implementation.

### SP-006 — Evidence integrity metadata

The schema must support references to hashes/revisions needed to identify relevant operations, configurations, artifacts and upstream specifications. Cryptographic signing of complete records is not required in Cycle 001.

### SP-007 — No customer-specific schema fields

The public schema must not encode client names, tenant-specific business entities or proprietary data models as first-class required fields.

## 7. Versioning

Cycle 001 establishes schema major version `1`.

Rules:

- additive optional fields may be introduced within a compatible v1 evolution;
- removing fields, changing required semantics or changing enum meanings requires a new major schema version;
- parsers must reject unsupported major versions rather than guessing semantics;
- records must carry their schema version explicitly.

## 8. Canonical representation

The public interchange representation will be JSON.

The normative machine contract will be JSON Schema.

Rust types are the primary implementation model, but the JSON Schema remains independently usable by non-Rust consumers.

## 9. Fixtures

Cycle 001 must publish at least four synthetic fixtures:

1. `PASS`;
2. `FAIL`;
3. `INCONCLUSIVE`;
4. `ERROR`.

Fixtures must not contain customer-derived data.

## 10. Non-goals

Cycle 001 does not implement:

- MCP discovery;
- active adversarial testing;
- AuthZEN/COAZ-MCP vectors;
- attack graph;
- database persistence;
- enterprise APIs;
- SaaS ingestion;
- cross-customer intelligence;
- cryptographic signing infrastructure;
- SIEM integrations;
- final CLI UX beyond what is strictly necessary for schema validation tests.

## 11. Technical direction

The implementation language is Rust.

The evidence capability should be isolated as a reusable library crate so future CLI, MCP, vector and graph crates can depend on the contract without creating circular dependencies.

Target direction:

```text
crates/
  dare-security-evidence/

schemas/
  evidence/
    v1/

examples/
  evidence/
```

## 12. Acceptance criteria

Cycle 001 is complete when:

- the v1 schema is committed under a stable public path;
- Rust types serialize/deserialize deterministically;
- schema validation is exercised in automated tests;
- PASS, FAIL, INCONCLUSIVE and ERROR synthetic fixtures exist;
- fixtures validate against the canonical schema;
- invalid fixtures are rejected;
- redaction behavior has explicit tests;
- unsupported schema major versions are rejected;
- `cargo fmt --all --check` passes;
- `cargo clippy --workspace --all-targets -- -D warnings` passes;
- `cargo test --workspace` passes;
- documentation explains verdict semantics and versioning.

## 13. Strategic principle

The evidence contract is infrastructure, not a report format.

It must remain small, inspectable, standards-friendly and independent from future proprietary product layers.
