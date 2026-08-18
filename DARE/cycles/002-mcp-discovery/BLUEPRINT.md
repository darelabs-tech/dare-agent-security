# Cycle 002 — Blueprint: Passive MCP Discovery and Enterprise Security Baseline

> Status: **ARCHITECTURE PROPOSED**
> Issue: #3
> Depends on: `DESIGN.md`, Cycle 001 evidence kernel

## 1. Architecture goal

Implement a passive MCP discovery subsystem and the first `dare-agent-security` CLI without weakening the Cycle 001 evidence boundary.

```text
                   explicit operator target
                            |
                            v
                  dare-agent-security CLI
                            |
                     PassivePolicy
                            |
                            v
                 dare-mcp-discovery
                  /       |       \
                 /        |        \
          lifecycle   enumeration   bounds
             adapter      engine     policy
                 \        |        /
                  \       |       /
                   DiscoveryInventory
                     /           \
                    /             \
       human baseline             JSON Schema
                    \             /
                     evidence bridge
                            |
                            v
                 dare-security-evidence
```

## 2. Workspace changes

Target layout:

```text
crates/
  dare-security-evidence/       # existing; dependency leaf
  dare-mcp-discovery/           # new library
  dare-agent-security-cli/      # new binary

schemas/
  evidence/v1/                  # existing
  discovery/v1/
    inventory.schema.json

labs/
  synthetic-mcp/

examples/
  discovery/
    complete.json
    partial.json

DARE/cycles/002-mcp-discovery/
  DESIGN.md
  BLUEPRINT.md
  TASKS.md
  dare-dag.yaml
  dag-graph.mmd
  EXECUTION/
```

## 3. Dependency rule

Required direction:

```text
dare-agent-security-cli
        |
        v
dare-mcp-discovery ---> dare-security-evidence
```

`dare-security-evidence` MUST NOT depend on MCP/discovery/CLI crates.

## 4. MCP SDK boundary

Use the official Rust MCP SDK (`rmcp`) for wire/lifecycle/transport primitives compatible with MCP `2026-07-28` and supported legacy revisions.

All SDK interaction is wrapped behind a local interface:

```rust
#[async_trait]
pub trait McpDiscoveryClient {
    async fn discover_server(&mut self) -> Result<ServerSnapshot, DiscoveryError>;
    async fn list_tools(&mut self) -> Result<Vec<ToolSnapshot>, DiscoveryError>;
    async fn list_resources(&mut self) -> Result<Vec<ResourceSnapshot>, DiscoveryError>;
    async fn list_resource_templates(&mut self) -> Result<Vec<ResourceTemplateSnapshot>, DiscoveryError>;
    async fn list_prompts(&mut self) -> Result<Vec<PromptSnapshot>, DiscoveryError>;
}
```

The public inventory model must not expose `rmcp` types.

## 5. Passive dispatch policy

Every outbound MCP method passes through an explicit method guard before the SDK/transport layer.

```rust
pub enum DiscoveryMethod {
    ServerDiscover,
    ToolsList,
    ResourcesList,
    ResourceTemplatesList,
    PromptsList,
    LegacyInitialize,
    LegacyInitialized,
}

pub trait PassivePolicy {
    fn authorize(&self, method: &str) -> Result<(), PolicyRefusal>;
}
```

Policy properties:

- allowlist, never denylist;
- unknown method => refuse;
- `tools/call` => refuse;
- `resources/read` => refuse;
- `prompts/get` => refuse;
- arbitrary extension methods => refuse;
- refused method never reaches transport;
- refusal errors contain method metadata only, never arguments/secrets.

## 6. Lifecycle strategy

### 6.1 MCP 2026-07-28

Use the current stateless discovery/version-negotiation mode. `server/discover` is allowed to learn server metadata/capabilities when needed. Enumeration requests carry the protocol/client metadata required by the SDK/spec version.

### 6.2 Legacy revisions

The adapter supports a bounded legacy lifecycle required by supported pre-2026 revisions. Initialization is a protocol compatibility concern and must not leak into the canonical inventory.

### 6.3 Negotiated revision

Persist the actual negotiated/selected protocol revision in the inventory. Unsupported revisions fail explicitly rather than being guessed.

## 7. Transport contracts

### 7.1 stdio

CLI shape:

```bash
dare-agent-security discover --stdio -- <command> [args...]
```

Rules:

- operator explicitly supplies executable and arguments;
- child stdout is protocol-only;
- child stderr may be captured as bounded diagnostics but is never embedded raw into evidence;
- execution timeout is mandatory;
- no shell interpolation: spawn executable/args directly;
- environment inheritance is explicit and documented.

### 7.2 Streamable HTTP

CLI shape:

```bash
dare-agent-security discover --url https://mcp.example.test/mcp
```

Rules:

- only explicit URL target;
- redirects disabled by default;
- target host is not expanded from discovered URIs;
- bounded connect/request timeout;
- bounded body size;
- credentials supplied through runtime/config references, never printed;
- TLS verification enabled by default;
- no automatic insecure downgrade.

## 8. Canonical `DiscoveryInventory`

Proposed Rust model:

```rust
pub struct DiscoveryInventory {
    pub schema: InventorySchemaRef,
    pub generated_at: String,
    pub target: DiscoveryTarget,
    pub protocol: ProtocolSnapshot,
    pub transport: TransportSnapshot,
    pub server: Option<ServerSnapshot>,
    pub capabilities: CapabilitySnapshot,
    pub auth: AuthSnapshot,
    pub tools: Vec<ToolInventory>,
    pub resources: Vec<ResourceInventory>,
    pub resource_templates: Vec<ResourceTemplateInventory>,
    pub prompts: Vec<PromptInventory>,
    pub indicators: Vec<BaselineIndicator>,
    pub warnings: Vec<DiscoveryWarning>,
    pub redaction: DiscoveryRedaction,
    pub hashes: Vec<DiscoveryHashRef>,
}
```

All public structs use `deny_unknown_fields` where compatible with safe forward versioning. Wire enums are explicit and have no security-sensitive implicit defaults.

## 9. Inventory schema version

Canonical path:

```text
schemas/discovery/v1/inventory.schema.json
```

Recommended `$id`:

```text
https://darelabs.tech/schemas/discovery/v1/inventory.schema.json
```

Rules:

- schema major v1;
- unsupported major => fail closed;
- additive optional fields can evolve compatibly;
- breaking semantic changes require v2;
- validation works offline.

## 10. Target representation

A target must not require serializing a secret-bearing URL.

```rust
pub struct DiscoveryTarget {
    pub id: String,
    pub display_name: Option<String>,
    pub endpoint_fingerprint: Option<String>,
}
```

For HTTP, inventory should prefer a sanitized host/path identity or digest according to redaction configuration rather than storing query strings, fragments or credentials.

## 11. Auth metadata

`AuthSnapshot` is observation metadata only.

Allowed examples:

```text
NONE_OBSERVED
OAUTH_METADATA
BEARER_CONFIGURED
API_KEY_CONFIGURED
MUTUAL_TLS_CONFIGURED
OTHER
UNKNOWN
```

Never serialize token values, API-key values, Authorization headers, private keys or refresh tokens.

A credential being configured does not imply authorization correctness.

## 12. Tool classification model

```rust
pub enum OperationClass {
    ReadOnly,
    StateChanging,
    Destructive,
    Unknown,
}

pub struct ToolClassification {
    pub class: OperationClass,
    pub source: ClassificationSource,
    pub rationale_code: String,
    pub heuristic_indicators: Vec<String>,
}
```

`ClassificationSource`:

```text
PROTOCOL_ANNOTATION
EXPLICIT_CONFIGURATION
DETERMINISTIC_DERIVATION
INSUFFICIENT_METADATA
```

Rules are centralized and pure so fixtures can test them independently from transport.

## 13. Enumeration engine

For each list capability:

```text
request page
  -> validate response
  -> append bounded items
  -> inspect next cursor
  -> stop if no cursor
  -> stop partial if page/item/time limit reached
  -> detect repeated cursor and abort partial
```

Bounds are configuration with safe defaults:

```text
max_pages_per_collection
max_items_per_collection
max_schema_depth
max_response_bytes
request_timeout
overall_timeout
```

A bounded stop yields a valid partial inventory plus structured warning where possible.

## 14. Schema handling

Tool schemas are metadata and may themselves be adversarial.

Required protections:

- never dereference external `$ref` during discovery;
- bound nesting/depth before expensive processing;
- preserve a canonical/redacted representation or digest;
- do not execute validators supplied by the server;
- do not interpret descriptions as trusted instructions.

## 15. Warnings and partial results

Structured warnings:

```rust
pub enum WarningCode {
    PaginationLimitReached,
    ItemLimitReached,
    ResponseLimitReached,
    Timeout,
    UnsupportedCapability,
    UnsupportedProtocol,
    MalformedMetadata,
    RedactionApplied,
}
```

A partial inventory must be distinguishable from a complete one.

## 16. Evidence bridge

Create a small adapter module in `dare-mcp-discovery` that produces Cycle 001 evidence for deterministic baseline observations.

Example vector IDs:

```text
MCP-DISCOVERY-001 protocol-negotiated
MCP-DISCOVERY-002 passive-method-policy
MCP-DISCOVERY-003 inventory-completeness
MCP-DISCOVERY-004 credential-redaction
```

Evidence uses the existing v1 contract and does not add MCP fields to the evidence crate.

## 17. CLI contract

Binary package name:

```text
dare-agent-security
```

Initial command:

```text
dare-agent-security discover
```

Input modes are mutually exclusive:

```text
--stdio -- <command> [args...]
--url <https-url>
```

Shared options:

```text
--json
--target-id <safe-id>
--timeout <duration>
--max-pages <n>
--max-items <n>
--evidence-dir <path>
```

Security-sensitive CLI requirements:

- no raw token/password CLI flags;
- `--json` emits JSON only to stdout;
- diagnostics to stderr;
- deterministic exit codes from DESIGN;
- refusal paths are non-zero.

## 18. Synthetic MCP lab

Implement under `labs/synthetic-mcp` using the official SDK and local synthetic data.

Fixtures expose:

```text
tools:
  customer.lookup          read-only
  reservation.update      state-changing
  reservation.delete      destructive
  legacy.ambiguous        unknown
resources:
  synthetic://fleet/catalog
  synthetic://reservation/policy
resource template:
  synthetic://vehicle/{id}
prompts:
  booking-summary
  fleet-support
```

No real company/customer names, credentials, URLs or business data.

The lab must provide deterministic pagination for at least one collection.

## 19. Tests

### Unit

- passive allowlist/refusal;
- operation classification;
- URL/credential redaction;
- pagination bounds and repeated cursor;
- version parsing;
- warning semantics;
- schema depth/size guards.

### Contract

For public inventory fixtures:

1. deserialize;
2. JSON Schema validate offline;
3. semantic validate;
4. serialize;
5. re-deserialize;
6. assert semantic equality.

### Integration

- synthetic stdio target;
- synthetic Streamable HTTP target;
- MCP 2026-07-28 lifecycle;
- one supported legacy lifecycle;
- multi-page list enumeration;
- partial result on configured bound.

### Safety proof

Instrument the lab to record received method names. E2E test asserts the complete set of outbound methods is a subset of the Cycle 002 allowlist and specifically proves absence of:

```text
tools/call
resources/read
prompts/get
```

## 20. CI gates

Required:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI must also validate:

- discovery JSON Schema offline;
- public fixtures;
- e2e passive-only method trace;
- no committed fixture secret patterns;
- CLI `--json` contract.

## 21. Documentation deliverables

- root README quick-start for `discover`;
- crate README for discovery architecture/safety;
- inventory schema/versioning docs;
- passive-operation policy documentation;
- synthetic lab instructions;
- current MCP version compatibility matrix.

## 22. Implementation phases

```text
P1 contracts + workspace
P2 passive policy + lifecycle/transport adapter
P3 enumeration + bounded parsing
P4 classification + redaction + evidence bridge
P5 CLI + synthetic lab
P6 e2e safety/compatibility proof + docs
```

## 23. Definition of architecture complete

Architecture is ready for execution when these invariants are accepted:

- discovery is allowlist-driven and passive;
- current and legacy MCP lifecycle details are isolated behind an adapter;
- inventory is a separate versioned contract;
- evidence remains generic and dependency-inward;
- `UNKNOWN` is preferred over unsafe inference;
- stdio and Streamable HTTP are explicit-target only;
- no raw credentials are output;
- all enumeration is bounded;
- safety is demonstrated by captured outbound-method traces, not documentation alone.