# Cycle 002 — Tasks: Passive MCP Discovery and Enterprise Security Baseline

> Status: **READY FOR REVIEW**
> Issue: #3
> Design: `DESIGN.md` (approved)
> Architecture: `BLUEPRINT.md` (pending human approval)

## Execution contract

Every implementation task must satisfy the workspace gates applicable at that point:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Cycle-wide invariants:

- no `tools/call` from discovery mode;
- no `resources/read` from discovery mode;
- no `prompts/get` from discovery mode;
- no recursive scope expansion;
- no raw secret material in inventory, evidence, logs or safe errors;
- no customer-derived fixtures;
- unsupported/ambiguous security semantics resolve to `UNKNOWN`, partial, inconclusive or explicit error — never guessed-safe;
- all outbound activity is restricted to the explicit operator target;
- protocol-specific SDK types do not leak into the canonical inventory contract;
- `dare-security-evidence` remains dependency-inward and MCP-agnostic.

## Task table

| ID | Task | Depends on | Complexity | Done when |
|---|---|---|---|---|
| task-001 | Bootstrap discovery + CLI crates | Cycle 001 | MEDIUM | workspace builds with correct dependency direction |
| task-002 | Implement Discovery Inventory v1 model + JSON Schema | task-001 | HIGH | canonical inventory validates offline and invalid records fail closed |
| task-003 | Implement passive MCP method policy | task-001 | HIGH | non-allowlisted methods are refused before transport dispatch |
| task-004 | Implement version-aware MCP client adapter | task-003 | HIGH | current + selected legacy lifecycle are isolated behind project interfaces |
| task-005 | Implement bounded enumeration engine | task-002, task-004 | HIGH | catalogs paginate safely with typed partial outcomes |
| task-006 | Implement deterministic tool classification | task-002 | HIGH | metadata maps deterministically; ambiguity yields UNKNOWN |
| task-007 | Implement redaction and target/auth sanitization | task-002, task-004 | HIGH | canary secrets never appear in public artifacts or errors |
| task-008 | Implement Cycle 001 evidence bridge | task-002, task-003, task-006, task-007 | MEDIUM | discovery observations emit valid SecurityEvidence v1 |
| task-009 | Build deterministic synthetic MCP lab | task-004, task-005, task-006 | HIGH | lab exposes mixed capabilities, pagination and method tracing |
| task-010 | Implement `dare-agent-security discover` CLI | task-005, task-006, task-007, task-008 | HIGH | stdio/URL modes, human output, JSON output and stable exit semantics work |
| task-011 | Add integration matrix + passive-safety proof | task-009, task-010 | HIGH | E2E trace proves only allowlisted methods reached the lab |
| task-012 | Documentation, CI, compatibility matrix and final proof | task-011 | MEDIUM | all Design acceptance criteria have concrete PASS/FAIL evidence |

## Phase A — Contracts and policy

### task-001 — Bootstrap discovery and CLI crates

Create:

```text
crates/dare-mcp-discovery/
crates/dare-agent-security-cli/
```

Required dependency direction:

```text
dare-agent-security-cli
        |
        v
dare-mcp-discovery ---> dare-security-evidence
```

The evidence crate must not depend on the new crates.

### task-002 — Discovery Inventory v1 model and schema

Create the typed Rust inventory contract plus:

```text
schemas/discovery/v1/inventory.schema.json
examples/discovery/complete.json
examples/discovery/partial.json
```

Implement structural and semantic validation, stable wire enums, schema-major fail-closed behavior and offline contract tests.

### task-003 — Passive MCP method policy

Centralize an allowlist guard for every outbound discovery request.

Allowed families are limited to the version-appropriate equivalent of:

```text
server/discover
tools/list
resources/list
resources/templates/list
prompts/list
legacy lifecycle operations strictly required for supported compatibility
```

Forbidden/unknown methods must never reach transport.

## Phase B — Protocol and bounded discovery

### task-004 — Version-aware MCP client adapter

Wrap the MCP Rust SDK behind project-owned interfaces.

Requirements:

- MCP `2026-07-28` first-class behavior;
- one explicitly supported pre-2026 compatibility path;
- stdio + Streamable HTTP;
- explicit target only;
- safe timeout/redirect behavior;
- no SDK types in public domain contracts.

### task-005 — Bounded enumeration engine

Enumerate tools, resources, resource templates and prompts with:

- cursor pagination;
- repeated-cursor detection;
- max pages/items/bytes/depth;
- request and overall timeouts;
- typed partial inventory outcomes.

Never dereference discovered resource URIs or external schema `$ref` values.

### task-006 — Deterministic tool classification

Classes:

```text
READ_ONLY
STATE_CHANGING
DESTRUCTIVE
UNKNOWN
```

Every classification records provenance and a rationale code. Descriptions/name heuristics may be recorded as non-authoritative indicators only. Insufficient metadata => `UNKNOWN`.

### task-007 — Redaction and sanitization

Protect URLs, auth headers, bearer/API-key values, environment-backed credentials, private-key-like material and transport/SDK errors.

Use canary-secret tests and assert absence from stdout, stderr, inventory and evidence.

## Phase C — Evidence, lab and CLI

### task-008 — Evidence bridge

Generate Cycle 001 `SecurityEvidence` records without modifying its schema.

Initial vector family:

```text
MCP-DISCOVERY-001 protocol-negotiated
MCP-DISCOVERY-002 passive-method-policy
MCP-DISCOVERY-003 inventory-completeness
MCP-DISCOVERY-004 credential-redaction
```

### task-009 — Synthetic MCP lab

Build `labs/synthetic-mcp` with synthetic-only data and deterministic pagination.

Expose at least:

- read-only tool;
- state-changing tool;
- destructive tool;
- ambiguous tool;
- resources;
- resource template;
- prompts;
- method trace capture.

### task-010 — CLI `discover`

Implement:

```bash
dare-agent-security discover --stdio -- <command> [args...]
dare-agent-security discover --url <https-url>
dare-agent-security discover ... --json
```

No raw credential CLI flags. JSON mode writes canonical JSON only to stdout; diagnostics go to stderr.

## Phase D — Proof and release readiness

### task-011 — Integration and passive-safety proof

E2E matrix includes current protocol, legacy compatibility, stdio, HTTP, pagination, bounded partial enumeration, forbidden-method refusal and credential-canary redaction.

Critical assertion:

```text
set(methods_received_by_lab) ⊆ Cycle002Allowlist
```

Explicitly prove absence of `tools/call`, `resources/read` and `prompts/get`.

### task-012 — Documentation, CI and final proof

Update README/docs/CI/compatibility matrix and produce the final cycle proof mapping every Design acceptance criterion to concrete tests/files/results.

## Completion definition

Cycle 002 is complete only when `discover` is useful against the synthetic lab, produces a versioned deterministic inventory, emits valid Cycle 001 evidence where applicable, supports current + explicitly defined legacy MCP behavior, and automated traces prove discovery performed no business-tool invocation or content retrieval.
