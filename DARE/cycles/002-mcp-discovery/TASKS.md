# Cycle 002 — Tasks: Passive MCP Discovery and Enterprise Security Baseline

> Status: **READY FOR EXECUTION AFTER BLUEPRINT APPROVAL**
> Issue: #3
> Design: `DESIGN.md`
> Architecture: `BLUEPRINT.md`

## Execution contract

Every task must satisfy:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Additional cycle invariants:

- no `tools/call` from discovery code;
- no `resources/read` from discovery code;
- no `prompts/get` from discovery code;
- no raw secret material in inventory/evidence/errors;
- no customer-derived fixtures;
- unsupported/ambiguous security semantics resolve to `UNKNOWN` or explicit error, never guessed-safe;
- outbound network/process activity is restricted to the explicit target supplied by the operator.

## Task table

| ID | Task | Depends on | Complexity | Done when |
|---|---|---|---|---|
| task-001 | Bootstrap discovery + CLI crates | Cycle 001 | M | workspace builds with correct dependency direction |
| task-002 | Implement Inventory v1 model + JSON Schema | 001 | H | canonical inventory validates offline and rejects invalid records |
| task-003 | Implement passive method policy | 001 | H | non-allowlisted MCP methods are refused before dispatch |
| task-004 | Implement version-aware MCP client adapter | 003 | H | 2026-07-28 and selected legacy lifecycle are isolated behind adapter |
| task-005 | Implement bounded enumeration engine | 002,004 | H | tools/resources/templates/prompts paginate safely with structured partial results |
| task-006 | Implement deterministic tool classification | 002 | H | explicit metadata maps to classes and insufficient metadata yields UNKNOWN |
| task-007 | Implement redaction + target/auth sanitization | 002,004 | H | credential-bearing inputs cannot appear in output or safe errors |
| task-008 | Implement Cycle 001 evidence bridge | 002,003,006,007 | M | deterministic discovery observations produce valid SecurityEvidence v1 |
| task-009 | Build synthetic MCP lab | 004,005,006 | H | deterministic local lab exposes mixed capabilities + pagination, no real data |
| task-010 | Implement `dare-agent-security discover` CLI | 005,006,007,008 | H | stdio/URL modes, human output, `--json`, stable exit codes |
| task-011 | Add integration + passive-safety proof | 009,010 | H | e2e trace proves only allowlisted methods were sent |
| task-012 | Documentation, CI compatibility matrix + final proof | 011 | M | all gates green and Cycle 002 acceptance criteria evidenced |

## task-001 — Bootstrap discovery and CLI crates

Create:

```text
crates/dare-mcp-discovery/
crates/dare-agent-security-cli/
```

Requirements:

- `dare-mcp-discovery` library depends on `dare-security-evidence`;
- CLI depends on discovery;
- evidence crate remains dependency-inward;
- add async/runtime/CLI dependencies only where required;
- no protocol-specific public types leak from the SDK into canonical domain models.

## task-002 — Inventory v1 model and schema

Create:

```text
schemas/discovery/v1/inventory.schema.json
examples/discovery/complete.json
examples/discovery/partial.json
```

Implement typed Rust model, structural + semantic validation, version checks and contract tests.

Required semantic checks include:

- supported schema major;
- non-empty target/protocol identifiers;
- complete vs partial state coherent with warnings;
- unique item identities where applicable;
- valid classification/source combinations;
- safe timestamps/hash metadata;
- no secret-bearing public fields.

## task-003 — Passive method policy

Implement a single dispatch gate used by every outbound discovery operation.

Allow only the protocol/version-appropriate equivalent of:

```text
server/discover
tools/list
resources/list
resources/templates/list
prompts/list
legacy initialization operations required for compatibility
```

Tests must attempt `tools/call`, `resources/read`, `prompts/get` and arbitrary extension methods and prove zero transport dispatch.

## task-004 — Version-aware MCP client adapter

Wrap the official Rust MCP SDK behind project-owned interfaces.

Requirements:

- MCP `2026-07-28` stateless discovery/version path;
- compatibility test for at least one supported pre-2026 revision;
- stdio and Streamable HTTP transports;
- explicit target only;
- redirects disabled by default for HTTP;
- bounded timeout/response behavior;
- no raw SDK types in inventory public API.

## task-005 — Bounded enumeration engine

Enumerate:

```text
tools
resources
resource templates
prompts
```

Requirements:

- cursor pagination;
- repeated-cursor detection;
- max-pages;
- max-items;
- response-size bound;
- schema-depth bound;
- per-request + overall timeout;
- partial inventory with typed warning when a safe bound stops enumeration.

Never dereference discovered resource URIs or external schema `$ref` values.

## task-006 — Deterministic tool classification

Implement pure classification rules:

```text
READ_ONLY
STATE_CHANGING
DESTRUCTIVE
UNKNOWN
```

Requirements:

- explicit trustworthy protocol annotations/config first;
- destructive semantics dominate;
- absent/ambiguous metadata => UNKNOWN;
- optional name/description heuristic may be recorded only as non-authoritative indicator;
- every classification records source + rationale code;
- table-driven tests for all combinations.

## task-007 — Redaction and sanitization

Protect:

- URLs with userinfo/query/fragment;
- Authorization headers;
- bearer/API-key values;
- environment-backed credentials;
- private-key material;
- transport/SDK error messages that may contain request metadata.

Requirements:

- sanitized target identity/fingerprint;
- redaction metadata in inventory;
- safe typed errors;
- no secret echo in stdout/stderr/evidence fixtures;
- tests use canary secrets and assert absence.

## task-008 — Evidence bridge

Generate valid Cycle 001 evidence for deterministic baseline vectors without modifying the evidence schema.

Initial vector IDs:

```text
MCP-DISCOVERY-001
MCP-DISCOVERY-002
MCP-DISCOVERY-003
MCP-DISCOVERY-004
```

At minimum prove:

- protocol discovery/negotiation result;
- passive policy enforcement;
- inventory completeness or explicit partial status;
- credential redaction property.

## task-009 — Synthetic MCP lab

Create `labs/synthetic-mcp`.

Expose synthetic capabilities described in Blueprint:

- read-only tool;
- state-changing tool;
- destructive tool;
- ambiguous tool;
- resources;
- resource template;
- prompts;
- deterministic pagination.

Lab records received MCP method names for safety tests.

## task-010 — CLI `discover`

Implement:

```bash
dare-agent-security discover --stdio -- <command> [args...]
dare-agent-security discover --url <https-url>
dare-agent-security discover ... --json
```

Requirements:

- modes mutually exclusive;
- no credential values in CLI flags;
- default human baseline;
- `--json` canonical inventory only on stdout;
- diagnostics stderr;
- stable exit codes 0/2/3/4;
- bounded configuration options;
- optional evidence artifact output.

## task-011 — Integration and passive-safety proof

Automated E2E matrix:

```text
stdio current protocol
HTTP current protocol
legacy compatibility
multi-page collection
bounded partial enumeration
forbidden-method refusal
credential canary redaction
```

Critical assertion:

```text
set(methods_received_by_lab) ⊆ Cycle002Allowlist
```

Explicitly assert absence of:

```text
tools/call
resources/read
prompts/get
```

## task-012 — Documentation, CI and final cycle proof

Update:

- root README quick start;
- discovery crate README;
- schema/versioning docs;
- passive policy docs;
- lab instructions;
- protocol compatibility matrix;
- GitHub Actions.

Final proof must report each DESIGN acceptance criterion as PASS/FAIL with concrete test/file references.

## Completion definition

Cycle 002 is DONE only when `discover` is useful against the synthetic lab, produces a versioned inventory and valid evidence, supports current + defined legacy MCP behavior, and the automated method trace proves the scanner performed no business-tool or content-fetch operation.