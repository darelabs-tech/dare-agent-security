# Cycle 002 — Passive MCP Discovery & Enterprise Security Baseline

> Status: **DESIGN READY FOR REVIEW**
> Tracks: #3
> Depends on: Cycle 001 — Deterministic Security Evidence Schema
> Proposed: 2026-08-18

## 1. Description

Cycle 002 builds the first useful scanner capability of DARE Agent Security: a safe, protocol-aware, non-intrusive MCP discovery pipeline that inventories a target server without invoking business tools or reading protected content.

The scanner will identify the protocol revision/era, transport, declared server capabilities, tools, resources, prompts, authentication/authorization metadata that can be observed safely, and security-relevant capability indicators. It will emit both a human-readable baseline and a deterministic machine-readable inventory that can be referenced by the Cycle 001 evidence contract.

This cycle is intentionally discovery-first. It does not attempt exploitation, authorization bypass, prompt injection, tool invocation, attack-path traversal, or COAZ/AuthZEN conformance testing.

## 2. Objectives and Success Metrics

| ID | Objective | Verifiable metric | Target |
|---|---|---|---|
| O-01 | Produce a useful passive MCP inventory | Declared tools/resources/prompts discovered in the synthetic lab | 100% of catalog items exposed by the lab through passive list operations |
| O-02 | Preserve a strict passive-scan boundary | State-changing/business tool invocations during default discovery | 0 `tools/call` requests |
| O-03 | Avoid content exfiltration during inventory | Content retrieval calls during default discovery | 0 `resources/read` and 0 `prompts/get` requests |
| O-04 | Support the current MCP protocol era | Synthetic server using MCP `2026-07-28` is discovered successfully | 1 fully passing modern lab scenario |
| O-05 | Preserve compatibility discipline | Legacy protocol behavior is either supported by a version-gated adapter or rejected explicitly | 100% of tested legacy fixtures produce a deterministic supported/unsupported result; no silent guessing |
| O-06 | Produce deterministic machine output | Two unchanged scans normalize to the same inventory payload excluding run-scoped metadata | 100% equality in contract test |
| O-07 | Keep secrets out of artifacts | Representative bearer/API-key/credential fixtures serialized into public scan output | 0 raw secrets |
| O-08 | Bridge discovery into the evidence kernel | Baseline findings can be represented as Cycle 001 evidence records without MCP-specific changes to the evidence crate | 100% of initial baseline rules emit valid v1 evidence when applicable |
| O-09 | Create the first CLI product surface | `dare-agent-security discover` operates against the synthetic lab | command exits deterministically with documented exit codes and JSON mode |

## 3. Stakeholders

| Role | Name / team | Primary interest |
|---|---|---|
| Project steward | DARE Labs | Safe OSS scanner wedge and stable product direction |
| Implementer | DARE Agent Security contributors | Clear protocol and crate boundaries |
| AppSec / Product Security user | Security engineering teams | Fast MCP inventory, risky capability visibility, reproducible evidence |
| IAM / Authorization user | Identity and authorization teams | Auth metadata, agent/tool surface, preparation for later AuthZEN/COAZ validation |
| MCP application developer | MCP server owners | CI-friendly feedback without destructive testing |
| Future enterprise control plane | Out of OSS scope for this cycle | Ability to ingest public inventory/evidence formats without coupling the OSS codebase to private infrastructure |

## 4. Functional Requirements

| ID | Priority | Requirement | Acceptance criterion |
|---|---|---|---|
| RF-01 | MUST | Accept an explicit MCP target definition | Scanner operates only on the operator-supplied endpoint/command; it never expands to neighboring hosts, ports, tenants, or services |
| RF-02 | MUST | Detect or negotiate the MCP protocol revision safely | The detected/selected revision is recorded; unsupported revisions fail explicitly rather than falling through to guessed semantics |
| RF-03 | MUST | Support MCP `2026-07-28` discovery semantics | The scanner can operate without relying on the retired legacy initialization/session model and can use `server/discover` when available without requiring it for every modern target |
| RF-04 | SHOULD | Provide version-gated compatibility for a supported 2025-era MCP revision | Legacy initialization is isolated behind a compatibility adapter and never leaks into modern protocol logic |
| RF-05 | MUST | Inventory declared capabilities | Server capabilities are captured in normalized form with the protocol revision that gave them meaning |
| RF-06 | MUST | Inventory tools | `tools/list` pages are collected, normalized, sorted deterministically, and emitted without calling any tool |
| RF-07 | MUST | Inventory resources | `resources/list` pages are collected, normalized, and emitted without reading resource content |
| RF-08 | MUST | Inventory prompts | `prompts/list` pages are collected, normalized, and emitted without resolving prompt bodies through `prompts/get` |
| RF-09 | MUST | Observe transport metadata | Inventory records the configured/observed transport and relevant protocol metadata without persisting credentials |
| RF-10 | MUST | Observe auth/authz metadata where safely available | Authentication requirement/mechanism or authorization metadata is represented as observed, declared, unknown, or not applicable; absence of metadata is not converted into a vulnerability claim |
| RF-11 | MUST | Classify security-relevant tool behavior conservatively | Tools may be classified as read-only, write/state-changing, destructive, external/open-world, or unknown only with explicit provenance such as declared hint, schema-derived signal, name heuristic, or unknown |
| RF-12 | MUST | Treat server annotations as untrusted hints | Self-reported annotations are preserved as declarations and are never elevated to proof of actual security behavior |
| RF-13 | MUST | Emit human-readable baseline output | Summary includes server/protocol, transport, capability counts, auth observation, risky capability indicators, and warnings/unknowns |
| RF-14 | MUST | Emit machine-readable JSON inventory | `--json` produces one documented, versioned inventory contract with deterministic field ordering/normalization semantics where applicable |
| RF-15 | MUST | Produce deterministic baseline findings | Initial rules use only observed/declarative inputs and include rationale/provenance; unknown data produces `INCONCLUSIVE`/informational output rather than fabricated certainty |
| RF-16 | MUST | Integrate with Cycle 001 evidence | Applicable baseline findings can be converted into valid `SecurityEvidence` records through an adapter that depends on `dare-security-evidence` |
| RF-17 | MUST | Provide a synthetic MCP discovery lab | Lab exposes multiple tools plus resources/prompts, mixed tool annotations, pagination, modern protocol metadata, and controlled auth metadata |
| RF-18 | SHOULD | Expose cache metadata without trusting stale state | Where list responses expose cache TTL/scope metadata, the scanner records it as protocol metadata but a fresh explicit scan can bypass local reuse |
| RF-19 | MUST | Bound pagination and response size | Discovery has configurable maximum pages/items/bytes and returns an explicit incomplete/error state when limits are reached |
| RF-20 | MUST | Document exit semantics | Success, findings, inconclusive/unsupported target, and scanner execution error have documented machine-consumable outcomes |

## 5. Non-Functional Requirements

| ID | Category | Requirement | Acceptance criterion |
|---|---|---|---|
| RNF-01 | Performance | Passive discovery completes with bounded I/O | Synthetic lab baseline completes within 10 seconds on local CI under normal conditions |
| RNF-02 | Determinism | Normalization is independent of server list ordering | Randomized catalog ordering produces the same normalized inventory |
| RNF-03 | Availability | Failure of one optional catalog does not corrupt successful observations from others | Partial scans are represented explicitly and remain machine-readable |
| RNF-04 | Security | Network/process inputs are treated as untrusted | Malformed JSON-RPC, oversized payloads, invalid pagination, and unsupported versions fail safely |
| RNF-05 | Secrets | Secrets are never required in output contracts | Target credentials may be consumed by an adapter from an external secret source but are never copied to inventory/evidence/logs |
| RNF-06 | Observability | Discovery decisions are explainable | Protocol selection, fallbacks, skipped operations, limits, and classification provenance are available in structured diagnostics |
| RNF-07 | Maintainability | Protocol-specific code is isolated from evidence | `dare-security-evidence` gains no MCP/network dependencies |
| RNF-08 | Testability | Network behavior is reproducible | Protocol adapters can run against deterministic synthetic transports/servers in CI |
| RNF-09 | Portability | Primary CLI remains suitable for developer workstations and CI | No database, SaaS, or container runtime is required for the scanner binary itself |
| RNF-10 | Dependency hygiene | New dependencies have an explicit need and audit path | Rust fmt/clippy/tests pass and dependency audit is included before cycle completion |

## 6. Security Requirements

| ID | Requirement | Verification |
|---|---|---|
| RS-01 | Validate all external MCP/CLI/config input before use | Negative tests for malformed URI/config, malformed JSON-RPC, bad pagination cursor/shape, unexpected fields, and unsupported protocol revision |
| RS-02 | Protect sensitive data in memory/output | Secret-like values are not part of public model contracts; representative bearer/API key/header secrets never appear in JSON, errors, or logs |
| RS-03 | Enforce target scope | Scanner contacts/spawns only the explicit configured target; no host/port/tenant enumeration or redirect-based scope expansion without an explicit allow decision |
| RS-04 | Audit dependencies | No known HIGH/CRITICAL dependency vulnerability is accepted without a documented disposition before cycle completion |
| RS-05 | Keep secrets outside source/config examples | Public fixtures reference environment-variable names or synthetic values only; no live credentials are committed |
| RS-06 | Default to passive behavior | The default discovery command has no code path that invokes `tools/call` |
| RS-07 | Do not retrieve protected content by default | Default discovery never invokes `resources/read` or `prompts/get` |
| RS-08 | Do not perform credential acquisition or harvesting | No OAuth login flow, token brute force, token extraction, filesystem credential search, or browser credential collection is implemented in Cycle 002 |
| RS-09 | Treat MCP descriptors and annotations as untrusted | Descriptions, schemas, annotations, names, URIs and icons are data only; they cannot cause command execution, file access, HTML rendering, network pivoting, or authorization decisions |
| RS-10 | Fail closed on protocol ambiguity | Scanner does not reinterpret a response under a different MCP revision without a defined version negotiation/fallback rule |
| RS-11 | Protect against unbounded catalog responses | Page count, item count, nested JSON size/depth where feasible, timeout and total response bytes are bounded |
| RS-12 | Avoid dangerous shell construction | STDIO targets, when supported, are spawned as program + argument vector without an intermediate shell by default |
| RS-13 | Restrict redirects and cross-origin movement | HTTP adapter must not silently follow redirects to a target outside the operator-approved origin/scope |
| RS-14 | Preserve evidence integrity | Every finding records the inventory revision/run reference and enough deterministic inputs to reproduce the rule result without embedding raw secrets |
| RS-15 | No LLM-as-judge | Tool classification heuristics and baseline verdicts are deterministic rule outputs; LLM prose cannot be the sole basis of a PASS/FAIL finding |

## 7. Technical Stack

| Layer | Technology / standard | Version / direction |
|---|---|---|
| Language | Rust | Workspace baseline: Rust 1.80, edition 2021 |
| Existing evidence kernel | `dare-security-evidence` | Cycle 001 v1 contract |
| MCP modern protocol | Model Context Protocol | `2026-07-28` first-class target |
| MCP compatibility | Model Context Protocol | One explicitly selected 2025-era compatibility path if implemented; exact revision fixed in Blueprint |
| Serialization | `serde` / `serde_json` | Reuse workspace approach; exact dependency versions remain pinned in Cargo.lock |
| CLI | Rust CLI crate | Exact crate/version to be fixed in Blueprint |
| HTTP transport | Rust HTTP client | Exact crate/version to be fixed in Blueprint; redirects disabled or scope-checked |
| STDIO transport | `std::process::Command` + async I/O as required | No shell by default |
| Machine contract | JSON + JSON Schema | Inventory schema v1 proposed |
| CI | GitHub Actions | Existing Rust fmt/clippy/test gates extended for new crates/lab |

## 8. External Integrations

| System | Type | Protocol | Direction | Data exchanged | Responsibility |
|---|---|---|---|---|---|
| MCP target | Runtime integration | MCP over supported transport | Scanner -> target | discovery/list RPCs and metadata only | Operator supplies explicit authorized target |
| MCP specification | Standards dependency | Published protocol specification | Read-only reference | revision semantics, method contracts | DARE Agent Security maintainers track compatibility |
| Cycle 001 evidence kernel | Internal OSS crate | Rust API / JSON Schema | Discovery -> evidence | normalized finding inputs and evidence records | DARE Agent Security |
| AuthZEN / COAZ-MCP | Future standards integration | Out of Cycle 002 | none in this cycle | none | Cycle 003 / Issue #4 |

## 9. Protocol Compatibility Contract

### 9.1 Modern MCP — `2026-07-28`

The modern adapter must model the 2026-era stateless protocol directly rather than emulating the retired initialize/session lifecycle.

Discovery rules:

1. `server/discover` may be attempted as a capability/version probe when appropriate for the transport.
2. The scanner must not require `server/discover` to exist in order to issue otherwise valid modern passive list requests when protocol selection is already known.
3. The scanner may use only non-business passive inventory calls in default mode, initially:
   - `tools/list`;
   - `resources/list`;
   - `prompts/list`.
4. The scanner records relevant per-request/per-response protocol metadata, but does not treat self-reported server identity as a trust anchor.
5. Streamable HTTP routing/version headers required by the selected revision are emitted by the transport adapter, not by baseline rules.

### 9.2 Legacy compatibility

Legacy compatibility must be explicit and isolated.

If a supported pre-2026 revision requires the older initialization handshake, that logic belongs in a legacy adapter. A modern response must never be silently reinterpreted as legacy, and a failed/ambiguous negotiation produces an explicit unsupported/inconclusive result.

### 9.3 Capability annotations

Tool annotations and descriptive fields are self-reported hints. The scanner may use them as one deterministic input to classification but must preserve their provenance and must not assert that a hint proves real runtime behavior.

## 10. Initial Security Baseline Semantics

Cycle 002 is primarily inventory, but it should surface deterministic baseline observations without pretending every observation is a vulnerability.

Initial categories:

- protocol revision and compatibility status;
- transport type and deprecated/legacy indicator where deterministically known;
- authentication state as `OBSERVED`, `DECLARED`, `UNKNOWN`, or `NOT_APPLICABLE`;
- catalog counts and pagination completeness;
- tool behavior declarations/hints;
- deterministic tool-name/schema heuristics with provenance;
- read/write/destructive/open-world indicators;
- unknown/unclassifiable tool operations;
- capability combinations that deserve later review;
- redaction/scope/protocol errors.

Severity is optional. Discovery observations must not be promoted to vulnerability severity solely because a tool is powerful or because auth metadata is unknown.

## 11. Output Contract

### 11.1 Human output

Target direction:

```text
DARE Agent Security — MCP Discovery

Target                  synthetic-rental-mcp
Protocol                2026-07-28
Transport               streamable-http
Discovery completeness  COMPLETE

Capabilities
Tools                    8
Resources                3
Prompts                  2

Tool behavior indicators
Read-only                3
State-changing           3
Destructive              1
Unknown                  1
Open-world               2

Authentication           OBSERVED
Warnings                 2
```

### 11.2 Machine output

Target direction:

```bash
dare-agent-security discover --config target.json --json
```

The JSON inventory must include a schema/version, target identifier, protocol/transport metadata, discovery completeness, catalog descriptors, classification provenance, auth observation metadata, scanner/spec revision metadata, redaction metadata, and baseline findings/references.

Run timestamps or volatile diagnostics must be separated from the normalized inventory identity so unchanged inputs can be compared deterministically.

## 12. Synthetic Lab Requirements

The public lab must use synthetic, non-customer data and expose enough variation to test the scanner:

- modern `2026-07-28` behavior;
- at least 8 tools;
- at least 3 resources;
- at least 2 prompts;
- paginated tool/resource or prompt listing;
- a mix of read-only, state-changing, destructive, idempotent and open-world declarations/hints where supported;
- at least one intentionally ambiguous tool that must remain `UNKNOWN` or low-confidence;
- deterministic server responses;
- synthetic auth metadata scenario;
- malformed/unsupported fixtures for negative tests;
- no live external service dependency.

Example domain may be a fully synthetic vehicle-rental system so later attack-graph and authorization vectors can reuse the same lab without exposing any real customer implementation.

## 13. Constraints

- Must preserve the generic/protocol-specific boundary established in Cycle 001.
- Must not add MCP concepts to required fields of the generic evidence schema.
- Must remain safe to run by default against an explicitly authorized enterprise MCP endpoint.
- Must remain useful without an LLM.
- Must be suitable for OSS release with synthetic fixtures only.
- Must not ingest or publish customer-specific endpoints, schemas, credentials, findings or source code.
- Must not require a database or SaaS control plane.

## 14. Out of Scope for Cycle 002

- `tools/call` execution of any business tool;
- resource body retrieval via `resources/read`;
- prompt body retrieval via `prompts/get`;
- active prompt injection or goal hijacking;
- authorization bypass testing;
- OAuth/DCR/CIMD client onboarding flows;
- token audience/passthrough testing;
- AuthZEN/COAZ-MCP conformance vectors (Issue #4 / planned Cycle 003);
- arbitrary network/port scanning;
- credential harvesting;
- attack graph construction/traversal;
- autonomous exploitation;
- persistence/database/SaaS ingestion;
- enterprise fleet management;
- customer-specific plugins in the public repository.

## 15. Risks and Mitigations

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Protocol churn causes scanner drift | Medium | High | Record protocol revision in every inventory; isolate adapters; test modern and legacy fixtures; avoid a single version-agnostic parser |
| Passive discovery accidentally becomes active testing | Medium | High | Hard API boundary that exposes list/discover operations only to default scanner; no `tools/call` method in passive execution interface |
| Tool annotations are trusted as truth | Medium | High | Model provenance and trust level; annotations are hints, not runtime proof |
| Descriptions/tool names cause false-positive risk classification | High | Medium | Deterministic heuristic provenance + confidence; keep ambiguous cases unknown; no vulnerability severity from names alone |
| Resource/prompt metadata leaks sensitive identifiers | Medium | Medium | Redaction layer, bounded descriptors, configurable URI/path normalization, no content reads |
| HTTP redirects escape authorized scope | Low/Medium | High | Disable redirects by default or require same-origin/explicitly allowed destination |
| Malicious MCP payload exhausts scanner resources | Medium | High | Timeouts, page/item/byte limits, bounded parsing and explicit partial/incomplete result |
| Legacy and modern semantics get mixed | Medium | High | Separate protocol adapters and explicit compatibility tests |
| CLI secrets leak through process arguments | Medium | High | Target config references secret sources/env names rather than raw tokens; never require bearer values in public command examples |
| Discovery model becomes a second generic evidence schema | Medium | Medium | Keep inventory as protocol-specific observation artifact; security verdict remains in Cycle 001 evidence kernel |

## 16. Acceptance Criteria

Cycle 002 implementation is complete only when all of the following are true:

- `dare-agent-security discover` exists and operates against the synthetic MCP lab;
- MCP `2026-07-28` is supported as a first-class protocol revision;
- at least one explicitly documented legacy compatibility/unsupported path is tested;
- tools/resources/prompts are inventoried through passive list operations with pagination;
- default discovery performs zero `tools/call`, zero `resources/read`, and zero `prompts/get` operations;
- capability/tool classifications include provenance and preserve `UNKNOWN` when evidence is insufficient;
- self-reported MCP annotations are not treated as security proof;
- auth metadata uses observed/declared/unknown semantics rather than guessing;
- human-readable baseline output exists;
- `--json` emits a versioned machine-readable inventory;
- normalized inventory is deterministic for unchanged synthetic input;
- at least one baseline result is emitted as a valid Cycle 001 `SecurityEvidence` record without changing the generic evidence model to become MCP-specific;
- synthetic fixtures contain no customer-derived data;
- representative secret values do not appear in output/errors/logs;
- malformed/oversized/unsupported protocol cases fail safely;
- scope/redirect tests prove the scanner does not expand beyond the configured target;
- `cargo fmt --all --check` passes;
- `cargo clippy --workspace --all-targets -- -D warnings` passes;
- `cargo test --workspace` passes;
- dependency audit has no unresolved HIGH/CRITICAL issue without documented disposition;
- documentation explains the passive-scan boundary, protocol compatibility policy, classification provenance and limitations.

## 17. Proposed Next Cycle

After Cycle 002 is implemented and merged, Cycle 003 should implement Issue #4: deterministic COAZ-MCP/AuthZEN authorization-to-execution integrity vectors against the synthetic lab and using the Cycle 001 evidence contract.

This sequence is intentional:

```text
Cycle 001: Evidence contract
          |
          v
Cycle 002: Passive MCP discovery + baseline
          |
          v
Cycle 003: Authorization conformance vectors
          |
          v
GitHub Action / authorized enterprise pilot
```

## 18. Approval Checklist

Review before generating the Cycle 002 Blueprint:

- [ ] The default scanner boundary is strictly passive.
- [ ] `tools/call`, `resources/read`, and `prompts/get` are correctly excluded from default discovery.
- [ ] MCP `2026-07-28` is the first-class modern protocol target.
- [ ] Legacy compatibility is explicit/version-gated rather than implicit.
- [ ] Inventory and generic security evidence remain separate contracts.
- [ ] Tool classification provenance/unknown handling is acceptable.
- [ ] The synthetic vehicle-rental-style lab is acceptable as the reusable public test domain.
- [ ] CLI + JSON output are part of Cycle 002.
- [ ] AuthZEN/COAZ-MCP remains Cycle 003.
- [ ] No customer/private data or proprietary integration is required for acceptance.
