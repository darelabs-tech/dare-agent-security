# Cycle 002 — Passive MCP Discovery and Enterprise Security Baseline

> Status: **DESIGN APPROVED FOR PLANNING**
> Issue: #3
> Depends on: Cycle 001 — Deterministic Security Evidence Schema
> Target protocol baseline: MCP `2026-07-28` with backwards-compatible discovery for supported legacy revisions

## 1. Objective

Build the first useful `dare-agent-security` product surface: a passive, deterministic MCP discovery command that inventories what an MCP server exposes without invoking business tools, reading resource contents, expanding scope, or harvesting credentials.

The primary user-facing flow is:

```text
MCP target
   |
   v
passive protocol discovery
   |
   +--> server / protocol / transport metadata
   +--> tools inventory
   +--> resources inventory
   +--> resource templates inventory
   +--> prompts inventory
   +--> declared capabilities
   +--> authorization metadata observable without secrets
   +--> deterministic risk indicators
   |
   v
versioned machine inventory
   |
   +--> human baseline summary
   +--> Cycle 001 SecurityEvidence records
```

Initial CLI direction:

```bash
dare-agent-security discover <target>
dare-agent-security discover <target> --json
```

## 2. Problem

Organizations are deploying MCP servers faster than security teams can answer basic questions:

- What MCP servers exist?
- Which protocol revision do they speak?
- Which tools, resources, templates and prompts are exposed?
- Which capabilities are declared?
- Which operations are explicitly annotated as read-only, state-changing or destructive?
- Which capabilities cannot be safely classified from trustworthy metadata?
- What authentication or authorization metadata is observable at the protocol boundary?
- Can the result be reproduced and fed into CI, research and later adversarial validation?

Without a deterministic inventory, later authorization tests and attack-graph construction start from incomplete or subjective assumptions.

## 3. Product thesis

Discovery is not a vulnerability scanner yet. It is the trusted inventory layer on which security validation is built.

DARE Agent Security must prefer:

```text
explicit protocol metadata > deterministic derivation > UNKNOWN
```

It must not promote an LLM guess or a tool-name heuristic into a security fact.

## 4. Primary use cases

### UC-201 — Local MCP inventory

A developer points the CLI at a local stdio MCP server and receives an inventory without executing exposed tools.

### UC-202 — Remote MCP inventory

A security engineer points the CLI at an explicitly authorized Streamable HTTP MCP endpoint and receives the same canonical inventory model.

### UC-203 — Enterprise baseline

An AppSec/Product Security team inventories multiple authorized MCP servers and compares exposed capabilities without ingesting customer secrets into the OSS tool.

### UC-204 — CI artifact

The machine-readable inventory is persisted and later diffed or consumed by conformance/security checks.

### UC-205 — Evidence bridge

Discovery facts and baseline findings can be represented as Cycle 001 `SecurityEvidence` records without changing the evidence kernel.

## 5. Protocol scope

Cycle 002 is version-aware.

### MCP 2026-07-28

The implementation must support the stateless lifecycle used by MCP `2026-07-28`, including `server/discover` when capability discovery is required and per-request protocol metadata as required by the selected SDK/transport.

### Legacy supported MCP revisions

For supported earlier revisions, discovery may use their initialization/version-negotiation lifecycle before enumeration.

The protocol adapter must isolate lifecycle/version differences from the canonical inventory model.

## 6. Passive-operation allowlist

Cycle 002 is fail-closed. Only discovery/introspection operations required to enumerate public MCP metadata are allowed.

Allowed when supported by the negotiated revision:

```text
server/discover
tools/list
resources/list
resources/templates/list
prompts/list
legacy initialization/version negotiation required before the list methods
```

Explicitly forbidden in Cycle 002:

```text
tools/call
resources/read
prompts/get
completion/complete
elicitation or sampling requests
state-changing task operations
arbitrary extension invocation
following links or URIs discovered in returned content
```

If a transport/SDK attempts an operation outside the allowlist, the discovery layer must refuse it before dispatch.

## 7. Security properties

### SP-201 — No business-tool execution

Discovery never sends `tools/call`.

### SP-202 — No resource-content collection

Discovery inventories resource metadata but does not call `resources/read`.

### SP-203 — No prompt-content expansion

Discovery inventories prompt metadata but does not call `prompts/get`.

### SP-204 — Explicit target only

The scanner communicates only with the target explicitly selected by the operator. It does not recursively discover or scan arbitrary hosts, URLs or resources returned by the server.

### SP-205 — No credential harvesting

Credentials may be supplied through an approved runtime mechanism needed to access an authorized target, but raw credentials must never be serialized into inventory, evidence, stdout diagnostics or fixtures.

### SP-206 — Deterministic classification

Security-relevant classification uses explicit protocol metadata or bounded deterministic rules. Insufficient metadata yields `UNKNOWN`, not a guessed safe classification.

### SP-207 — Bounded discovery

Pagination, response size, schema depth, timeouts and item counts must be bounded to prevent a malicious or broken MCP server from exhausting local resources.

### SP-208 — Evidence compatibility

The discovery package depends inward on `dare-security-evidence`; the evidence kernel must not depend on discovery/MCP code.

## 8. Canonical inventory

Cycle 002 introduces a versioned machine-readable `DiscoveryInventory` separate from the generic evidence record.

Required top-level information:

- inventory schema identifier/version;
- generated timestamp;
- target-safe identifier;
- negotiated MCP protocol revision;
- transport type;
- server identity/version when exposed;
- declared capabilities;
- tools;
- resources;
- resource templates;
- prompts;
- observable authorization metadata without secret values;
- deterministic security/risk indicators;
- collection warnings/partial-result reasons;
- redaction metadata;
- source/config/protocol hashes where available.

The canonical interchange format is JSON with a committed JSON Schema.

## 9. Capability classification

Each tool receives an explicit classification state derived from trustworthy metadata available in the negotiated protocol representation.

Initial vocabulary:

```text
READ_ONLY
STATE_CHANGING
DESTRUCTIVE
UNKNOWN
```

Rules:

1. `UNKNOWN` is the default when authoritative metadata is insufficient.
2. Explicit destructive metadata dominates read-only semantics.
3. Explicit state-changing/non-read-only metadata prevents `READ_ONLY` classification.
4. Human-readable names/descriptions may generate a non-authoritative `heuristic_indicator`, but cannot alone produce a security verdict or upgrade `UNKNOWN` to `READ_ONLY`.
5. The source of every classification must be recorded.

## 10. Baseline indicators

Cycle 002 may emit deterministic baseline indicators such as:

- anonymous/no-auth metadata observed where the target was intentionally reachable without credentials;
- tool capability exposed;
- resource capability exposed;
- prompt capability exposed;
- destructive/state-changing annotation present;
- operation classification unknown because metadata is insufficient;
- unusually broad schema surface above a configured threshold;
- unsupported or unexpected protocol revision;
- partial enumeration due to timeout, pagination bound or protocol error.

Indicators are facts or bounded observations, not vulnerability severity claims unless a deterministic security property exists.

## 11. Machine and human output

### Human output

Default output is a concise baseline, for example:

```text
DARE Agent Security — MCP Discovery
Target: rental-fleet-mcp
Protocol: 2026-07-28
Transport: streamable-http

Tools                 18
Resources              7
Resource templates     3
Prompts                 4

Tool classification
Read-only              9
State-changing         4
Destructive            2
Unknown                3

Warnings               1
```

### JSON output

`--json` prints only the canonical inventory JSON to stdout. Diagnostics go to stderr.

## 12. Evidence bridge

Discovery does not overload `SecurityEvidence` as an inventory database.

Instead:

```text
DiscoveryInventory
      |
      +--> inventory artifact
      |
      +--> zero or more baseline observations
                    |
                    v
             SecurityEvidence v1
```

The bridge must reference sanitized inventory artifacts and deterministic observations.

## 13. Synthetic lab

Cycle 002 ships a local synthetic MCP lab containing at minimum:

- multiple tools;
- one explicitly read-only tool;
- one state-changing tool;
- one destructive tool;
- one intentionally ambiguous/unknown tool;
- multiple resources;
- at least one resource template;
- multiple prompts;
- deterministic pagination coverage;
- no real credentials or customer-derived data.

The lab must support the protocol mode required by the e2e tests and remain safe to run locally.

## 14. Non-goals

Cycle 002 does not implement:

- `tools/call` adversarial testing;
- COAZ-MCP/AuthZEN authorization integrity vectors;
- prompt injection testing;
- resource-content scanning;
- tool poisoning exploitation;
- credential collection;
- attack graph construction;
- recursive network discovery;
- SaaS persistence;
- customer-specific integrations;
- automated vulnerability severity from LLM judgement.

These belong to later cycles.

## 15. Technical direction

Rust remains the canonical implementation language.

Target dependency direction:

```text
                 dare-security-evidence
                         ^
                         |
                 dare-mcp-discovery
                         ^
                         |
                 dare-agent-security
                       CLI
```

Use the official MCP Rust SDK where it provides the required client/lifecycle/transport primitives, but wrap it behind project-owned interfaces so the canonical inventory and passive-operation policy are not coupled to SDK internals.

## 16. Exit codes

Initial stable CLI semantics:

```text
0  discovery completed and inventory is structurally/semantically valid
2  discovery completed partially; inventory is valid and contains explicit warnings
3  target/protocol/transport error prevented a valid inventory
4  local policy refused an unsafe/non-allowlisted operation or configuration
```

No partial/error condition may be silently converted to success.

## 17. Acceptance criteria

Cycle 002 is complete when:

- `dare-agent-security discover` exists;
- `--json` emits canonical JSON only on stdout;
- stdio discovery works against the synthetic MCP lab;
- authorized Streamable HTTP discovery is covered by automated integration tests;
- MCP `2026-07-28` lifecycle/discovery is supported;
- at least one supported legacy MCP lifecycle is covered by compatibility tests;
- tools/resources/resource templates/prompts can be enumerated with pagination bounds;
- forbidden methods cannot be dispatched through the discovery layer;
- classification defaults safely to `UNKNOWN` when metadata is insufficient;
- no raw credential is serialized or echoed in errors;
- the versioned inventory JSON Schema is committed and validated offline;
- inventory can emit/reference Cycle 001 evidence records for baseline observations;
- the synthetic lab and fixtures contain no customer data;
- `cargo fmt --all --check` passes;
- `cargo clippy --workspace --all-targets -- -D warnings` passes;
- `cargo test --workspace` passes;
- end-to-end tests prove passive-only behavior.

## 18. Strategic principle

The scanner must know the difference between **observed**, **derived** and **unknown**.

That distinction is foundational for every later DARE Agent Security capability: authorization validation, adversarial testing, attack graphs, CI gates and enterprise evidence.