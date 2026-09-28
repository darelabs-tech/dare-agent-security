# Cycle 023 — Design: Attack-Path Construction

**Version:** v0.2 | **Date:** 2026-09-28 | **Status:** DESIGN APPROVED  
**Base branch:** `main` (`32909ea`, Cycles 001–022 merged, including the Cycle 022 hotfix, PR #47)  
**Proposed crate:** `crates/dare-attack-path`  
**Also touched:** `crates/dare-attack-graph` (additive v2 contract and the path-engine
defects in §4.9). Engine crates 013–022 stay unchanged (Q3 decided: no engine change).  
**Approval:** APPROVED (Design phase) 2026-09-28 — see `APPROVAL.md`. Execution is not yet authorized.

---

## 1. Description

Cycle 008 delivered an attack-graph **engine** but not the **construction** of the
graph. `validate attack-graph` accepts only a normalized facts file written by hand
(`GraphFactsInput`: nodes, edges, evidence states, authority). The fixtures in
`fixtures/attack-graph/` are all hand-written. Nothing in the repository turns the
evidence produced by Cycles 013–022 into nodes, edges or paths.

Those cycles now produce a lot of relationship evidence:

| Cycle | Relationships already observed or declared |
|---|---|
| 014 tool | surface → tool, tool output → induced tool, tool chains, objective → selected tool |
| 015 identity | principal → principal delegation chains, principal → tool → resource operations, credential → owner, capabilities and tenants, resource → tenant and owner |
| 016 memory | writer → memory item → recall by another principal or tenant → influence on objective, tool selection or arguments |
| 017 RAG | document provenance → collection → tenant, retrieval by a principal, retrieved content → influence |
| 018 MCP auth | inbound and upstream credentials, resource → authorization server, authorized vs performed principal, tenant, resource and scopes |
| 019 supply chain | component dependency graph (`DEPENDS_ON`, `EXPOSES_TOOL`, `CONNECTS_TO`, `LOADS`, …) over 14 component types |
| 020 A2A | peers, Agent Cards, skills, delegation hops with subject, audience, tenant and allowed skills |
| 013 / 021 | untrusted input channels and cross-turn findings delegated to owning properties |
| 022 remote | the same engines' evidence, now `DYNAMIC_AUTHORIZED` |

Each engine judges its own boundary in isolation. None can say that a FAIL at one
boundary *connects* to a FAIL at another. For example, a poisoned document retrieved
across tenants (017) can steer tool selection (017 influence) toward a tool that runs
under a delegated credential wider than the user's (015) and reads another tenant's
records. That chain is the question an AppSec team actually asks.

Cycle 023 adds **evidence-derived attack-path construction**:

1. **Projectors**, one per engine, read an engine's existing artifacts: result and
   evidence, plus the input documents whose digests the result pins. Each emits
   **graph facts** with provenance. They add no verdict logic and never re-judge a
   property.
2. An explicit **system model** (a new, human-authored input) resolves engine-local
   identifiers into shared graph entities. There is no fuzzy or name-based merge. An
   identifier the model does not map stays a separate, engine-scoped node.
3. The Cycle 008 builder merges the facts into one graph. A new **path engine** then
   enumerates paths from declared **entry points** to declared **targets**, bounded and
   deterministic. Every truncation is reported, never silent.
4. Each path is classified on two independent axes. **Evidence state** is the Cycle 008
   `PROVEN` / `INFERRED` / `NOT_TESTED`. **Control state** says whether the security
   properties guarding the path's edges were observed to FAIL, were not decided, or
   held.

The engine answers one question:

> Given the artifacts *A₁…Aₙ* and the system model *M*, which chains of relationships
> connect an entry point to a target, and on which of them did every guarding control
> hold, did at least one control fail, or was a control not decided?

It does **not** say an unlisted path is impossible, and it does not compute a
probability or a risk score. It does not execute any path; controlled execution
remains Cycle 009's job and remote execution Cycle 022's. It does not measure blast
radius (Cycle 024).

---

## 2. Objectives and success metrics

| # | Objective | Verifiable metric | Target |
|---|-----------|-------------------|--------|
| O-01 | Construction from real artifacts | ATTACK-PATH-LAB scenarios whose graph is built by projectors only, with no hand-written facts | 100 % |
| O-02 | Path recall on ground truth | Expected entry → target paths in ATTACK-PATH-LAB that are reported | 100 % |
| O-03 | No invented edge | Reported edges that do not trace to an artifact record, an input document or a system-model declaration | 0 |
| O-04 | No false "controls held" | Paths reported `CONTROLS_HELD` that contain an edge whose guarding property is FAIL, INCONCLUSIVE, ERROR or unassessed | 0 |
| O-05 | Honest truncation | Runs that hit a bound and do not report `truncated: true` with the counts of what was skipped | 0 |
| O-06 | Determinism | The same artifacts and model give a byte-identical graph and path list | 10/10 runs |
| O-07 | Provenance binding | Artifacts whose pinned input digest mismatches the input supplied, and which are accepted | 0 (all refused) |
| O-08 | Compatibility | Cycle 008 v1 output for the existing facts fixtures, and Cycle 009 / 010 consumers of `Path` / `PathStatus` | byte-identical / unchanged |
| O-09 | Boundedness | Largest lab graph (≥ 2 000 nodes, ≥ 10 000 edges, synthetic) built and enumerated within the bounds of §4.6 | < 10 s, no bound overshoot |

---

## 3. Stakeholders

| Role | Name / team | Main interest |
|------|-------------|---------------|
| Product Owner | DARE Labs | Scope, approval, and the boundary with Cycles 024–025 |
| Tech Lead | DARE Agent Security maintainers | One graph model (Cycle 008), projectors outside the engines, no second verdict system |
| AppSec / red team | Primary users | Which FAILs chain into a path to something that matters, and which control to fix first |
| Architects / platform owners | Customer | A system model they can write and review, and paths that name their own components |
| Security reviewers | DARE Review | Every edge traceable to evidence; no path made to look safer or worse than the evidence says |

---

## 4. Functional requirements

| ID | Requirement | Priority | Acceptance criterion |
|----|-------------|----------|----------------------|
| RF-01 | Projectors for engines 014–020 | MUST | One projector per engine turns `<engine>-result.json` plus `<engine>-evidence.json` plus the pinned input documents into graph facts (§4.2). Each projector has a closed mapping table from engine relationship kinds to Cycle 008 edge types. A kind with no mapping is reported as `unprojected` with a count, never dropped silently |
| RF-02 | Projectors for 013, 021 and 022 | MUST | 013 and 021 contribute **entry-point** facts (untrusted input channels) and property outcomes, not topology. 022 contributes the same facts as the owning engine's projector, tagged `DYNAMIC_AUTHORIZED`. The 022 projector reads `remote-result.json` as JSON validated against `schemas/remote-validation/v1/result.schema.json` and hands each `engine_result` to the owning engine's projector. It does **not** depend on the `dare-remote-validation` crate (RNF-04) |
| RF-03 | Input binding | MUST | A projector accepts an input document only if its digest equals the digest the engine result pinned (for example `tool_digests`, `card_digest`, `delegation_chain_digest`, `item_digests`, `document_digests`). A mismatch is a refusal (exit 3). An artifact with no pinned digest for an input contributes result and evidence facts only |
| RF-04 | System model | MUST | A new schema, `schemas/attack-path/v1/system-model.schema.json` (§4.3), declares entities, aliases from engine-local ids to entities, entry points, targets and trust boundaries. It is admitted like every other input (size, depth, hostile sweep, `additionalProperties: false`) |
| RF-05 | Entity resolution | MUST | Engine-local ids merge only through an explicit alias in the system model. Without a model, or for an unaliased id, the node id is scoped by engine (`node:<type>:<engine>.<local_id>`) and never merged with another engine's node. Conflicting aliases (one local id mapped to two entities, or incompatible node types) are refused |
| RF-06 | Edge evidence state | MUST | The Cycle 008 states and invariants are reused unchanged. The Blueprint fixes a closed table: an event observed in a trace with an evidence record is `OBSERVED`; a relationship read from a pinned input document is `STATICALLY_PROVEN`, citing the input digest (Q2); a relationship declared only in the system model is `INFERRED`, with the model's rationale; a declared relationship that no engine evaluated is `NOT_TESTED` |
| RF-07 | Property binding per edge | MUST | Each edge carries the list of properties that guard it, with their verdicts and evidence ids, taken from the engines' evidence records. A closed mapping table (property id → guarded edge types and endpoint roles) extends Cycle 008's `BUILTIN_MAPPINGS`. It is tested against the real v1 and v2 registries |
| RF-08 | Entry points and targets | MUST | Paths are enumerated only from entry points to targets. Entry classes: `UNTRUSTED_INPUT`, `EXTERNAL_CONTENT`, `RETRIEVED_DOCUMENT`, `MEMORY_WRITE`, `PEER_AGENT`, `SUPPLY_CHAIN_COMPONENT`, `LOW_PRIVILEGE_PRINCIPAL`. Target classes: `SENSITIVE_RESOURCE`, `PRIVILEGED_CREDENTIAL`, `DESTRUCTIVE_CAPABILITY`, `CROSS_TENANT_RESOURCE`, `EXTERNAL_PUBLICATION`. Defaults come from node security flags and projector facts; the system model may add or remove them |
| RF-09 | Path engine v2 | MUST | Bounded enumeration of simple paths from entry to target, in a deterministic order (edge count, then path id). Every bound that stops the search is reported (`truncated`, the bound that fired, and the counts of entries and targets not exhausted). Hard maxima in §4.6 |
| RF-10 | Authority continuity | MUST | A path is **feasible** only if consecutive edges carry compatible authority, according to a closed rule table in the Blueprint. For example, a delegation edge must hand to the principal the next edge acts as. An authority change that is not explained by a delegation, credential or `AUTHENTICATES_AS` edge makes the path `DISCONTINUOUS`. Discontinuous paths are reported separately, never mixed with feasible ones |
| RF-11 | Control state per path | MUST | `CONTROL_FAILED` if any guarding property on the path is FAIL. Otherwise `CONTROL_UNDECIDED` if any guarding property is INCONCLUSIVE, ERROR or not assessed, or if an edge has no guarding property at all. Otherwise `CONTROLS_HELD`. This is the Cycle 018 precedence (FAIL > ERROR > INCONCLUSIVE > PASS) applied along a path. It is independent of evidence state and is **not** a verdict |
| RF-12 | Chokepoints | MUST | For each target, the edges (and their guarding properties) that appear on every enumerated `CONTROL_FAILED` path to it. These are reported as counts over the enumerated set, flagged `partial` when truncated. No score and no weighting |
| RF-13 | Artifacts | MUST | `attack-graph.json` (schema v2, §4.7), `attack-paths.json`, `projection-report.json` (per artifact: facts emitted, unprojected kinds, refused inputs), `graph.mmd` and `graph.dot` (derived views, labels escaped as in Cycle 008), and `summary.md`. Every artifact is admitted through the output ledger and redaction checks before it is written |
| RF-14 | CLI | MUST | `dare-agent-security validate attack-paths` with `--artifacts <dir>` (repeatable), optional `--system-model <path>`, `--output-dir`, and lower-only bounds. `validate attack-graph --facts` keeps working unchanged |
| RF-15 | ATTACK-PATH-LAB | MUST | At least 25 synthetic scenarios, each a set of real engine artifacts produced by running the engines on lab inputs, with an expected path list and states (§4.5). Every chain class has a control twin in which one guarding control holds and the path becomes `CONTROLS_HELD` or disappears |
| RF-16 | Product integration | SHOULD | `dare-product` fills `attack-graph.json` in a run from the derived graph when engine artifacts are present, instead of the empty object it writes today |
| RF-17 | Cycle 009 / 010 compatibility | MUST | `dare-adversarial::ensure_path_eligible` and `dare-continuous` drift keep working on the v1 `Path` and `PathStatus`. v2 paths expose the same `status` and `impact_factors`, so an eligible v2 path is still checked by the same rules |
| RF-18 | Path-engine defect correction | MUST | See §4.9 |

### 4.1 What a projector may and may not do

**May:**
- read an engine's result, evidence and the input documents pinned by the result;
- emit nodes, edges, entry and target candidates, and property bindings, each carrying
  provenance: engine, artifact digest, record or event locator, and input digest.

**May not:**
- change or recompute a verdict;
- read anything not pinned by the artifact;
- follow a URI;
- call the network;
- merge identities without the system model;
- invent an edge that no record, input or model declaration states.

### 4.2 Projection sources (v1)

| Engine | Topology source | Guarding properties (examples) |
|---|---|---|
| 014 tool | `ToolSurfaceSnapshot`, `ToolSelected`, `ToolOutputObserved{induced_tool_id}`, `ToolChainStep`, `POLICY_DECISION` | `AGENT.TOOL.AUTHORIZATION_BOUNDARY`, `…OUTPUT_TRUST_BOUNDARY`, `…CHAIN_BOUNDARY` |
| 015 identity | `Principal`, `DelegationChain.edges`, `Operation`, `CredentialContext*`, `ResourceContext` | `AGENT.IDENTITY.DELEGATION_INTEGRITY`, `…PRIVILEGE_AMPLIFICATION`, `…TENANT_RESOURCE_BOUNDARY` |
| 016 memory | `MemoryWriteObserved`, `MemoryRecallObserved`, `MemoryInfluenceObserved` | `AGENT.MEMORY.*` |
| 017 RAG | `DocumentStore` (collections, documents, provenance), `RetrievalContext`, `ResolvedDocument`, influence events | `AGENT.RAG.TENANT_DOCUMENT_ISOLATION`, `…CONTENT_TRUST_BOUNDARY`, `…PROVENANCE_INTEGRITY` |
| 018 MCP auth | `CredentialContext{inbound, upstream}`, `ResourceContext`, `FinalOperationContext` | `MCP.AUTH.*`, `MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY` |
| 019 supply chain | `RelationshipGraph` from the pinned SBOM and manifest inputs (Q3) | `AGENT.SUPPLY_CHAIN.*` |
| 020 A2A | `PeerRecord`, `ExchangeRecord`, `AgentCard` skills, `DelegationChain.hops` | `AGENT.A2A.*` |
| 013 / 021 | Source channels (`SourceKind`), and `DelegatedFinding{owning_property}` | `AGENT.GOAL.*`, multi-turn properties |
| 022 | The owning engine's projector, run over `engine_result` | as the owning engine |

### 4.3 System model (fields)

| Field | Meaning |
|---|---|
| `schema_version` | `"1"` |
| `model_id`, `target_id`, `target_version` | Validated identifiers, recorded in the graph provenance |
| `entities[]` | `{entity_id, type (a Cycle 008 NodeType), display_name, security: {tenant, privileged, sensitive, destructive}}` |
| `aliases[]` | `{engine, local_id, entity_id}` — the **only** way two engine-local ids become one node |
| `entry_points[]`, `targets[]` | `{entity_id, class}`, adding to or overriding the defaults (RF-08); `exclude: true` removes a default |
| `trust_boundaries[]` | Named sets of entities. A crossing edge is annotated `CROSSES_TRUST_BOUNDARY` |
| `declared_edges[]` | Optional relationships that no engine observes, each with a mandatory `rationale`. Always `INFERRED` (RF-06) |

### 4.4 Path classification

| Axis | Values | Source |
|---|---|---|
| Evidence state | `PROVEN` \| `INFERRED` \| `NOT_TESTED` | Cycle 008 weakest-edge rule, unchanged |
| Feasibility | `FEASIBLE` \| `DISCONTINUOUS` | RF-10 authority continuity |
| Control state | `CONTROL_FAILED` \| `CONTROL_UNDECIDED` \| `CONTROLS_HELD` | RF-11 |
| Impact factors | Cycle 008's six booleans, plus `crosses_trust_boundary` and `entry_class` / `target_class` | Deterministic annotations, not a score |

A report must never present `CONTROLS_HELD` as "secure": the summary states that only
enumerated paths over observed and declared relationships are covered.

### 4.5 ATTACK-PATH-LAB (at least 25 scenarios)

Each scenario runs the real engines on lab inputs to produce artifacts, then runs the
projectors. Hand-written facts are not allowed (O-01).

| Range | Chain class |
|---|---|
| 001–004 | Poisoned retrieved document → influence on tool selection → tool → cross-tenant resource (017 → 014 → 015) |
| 005–008 | Memory write by principal A → recall by B → tool argument → privileged credential (016 → 014 → 015) |
| 009–012 | Peer agent → delegation hop amplification → skill → downstream resource (020 → 015) |
| 013–015 | Supply-chain component → `EXPOSES_TOOL` → tool → credential (019 → 014 → 015/018) |
| 016–018 | MCP upstream credential passthrough → performed scope wider than authorized → resource (018 → 015) |
| 019–021 | Untrusted input (013) or a cross-turn finding (021) → tool chain → destructive capability |
| 022–023 | Discontinuous chains: unexplained authority change → reported `DISCONTINUOUS`, not feasible |
| 024–025 | Entity resolution: the same id in two engines without an alias → two nodes, no path; with an alias → merged, path appears |
| + | For every class, a control twin (one guarding property PASS) and a `NOT_TESTED` twin (the engine not run) |

### 4.6 Hard maxima (input may only lower them)

| Maximum | Value |
|---|---|
| Nodes | 10 000 (Cycle 008 schema) |
| Edges | 50 000 (Cycle 008 schema) |
| Path length | 12 edges |
| Paths reported per run | 10 000 |
| Paths per (entry, target) pair | 64 |
| Search steps per run | 5 000 000, then stop with `truncated` |
| Input artifacts per run | 64 |
| Artifact or input size | 16 MiB each |

### 4.7 Attack graph schema v2

`schemas/attack-graph/v2/attack-graph.schema.json` is additive over v1:
- node and edge `provenance[]`;
- edge `guards[]`, with property, verdict and evidence ids;
- `entry_points`, `targets`;
- path `feasibility`, `control_state`, `entry_class`, `target_class`;
- a top-level `enumeration` block (bounds, `truncated`, skipped counts);
- `model_digest` and per-artifact digests in `sources`.

v1 stays the output of `validate attack-graph --facts`, byte-identical for existing
inputs. The node and edge type enums are unchanged (Q4).

### 4.8 Hostile / refusal corpus

- **Artifacts:**
  - an input digest mismatch;
  - a duplicate or tampered evidence record (the evidence id is not found, or the digest differs);
  - an unknown engine;
  - an oversized or over-deep artifact;
  - labels carrying Mermaid/DOT injection or credential shapes.
- **System model:**
  - conflicting aliases;
  - an alias to an unknown entity;
  - a type clash;
  - `declared_edges` without a rationale;
  - more than the maxima.
- **Graphs:**
  - path explosion (a dense lab graph) → a bounded, reported truncation;
  - cycles;
  - self-edges.

### 4.9 Path-engine defect correction (found while drafting)

The Cycle 008 path engine (`crates/dare-attack-graph/src/path.rs`) has defects that
Cycle 023 inherits if it builds on it:

1. **`unwrap()` in production** (`make_path`, line 140), against the repository rule.
2. **Silent truncation.** When `max_paths` is hit, the search stops. The output does
   not say so, and which paths are kept depends on node-id order.
3. **Sink-only emission.** Without a target filter, a path is emitted only when it
   ends at a node with no outgoing edge. A path to a sensitive resource that has an
   outgoing edge is reported only as a longer path, or never, if the bound fires first.
4. **O(n) lookups per step** (`graph.edges.iter().find`), which makes enumeration
   quadratic on large graphs.

**Correction:**
- The v2 engine fixes all four.
- For v1, item 1 is fixed without changing output.
- Items 2–4 stay as they are in v1 (Q5), so Cycle 009 / 010 artifacts do not change.
- `REGRESSION.md` records the decision.

---

## 5. Non-functional requirements

| ID | Category | Requirement | Target |
|----|----------|-------------|--------|
| RNF-01 | Determinism | Same inputs → byte-identical outputs; ordering is defined on ids, never on hash-map or file-system order | 10/10 |
| RNF-02 | Boundedness | §4.6 maxima enforced before the step that would exceed them | 0 overshoot |
| RNF-03 | Performance | Full ATTACK-PATH-LAB in CI | < 60 s on `ubuntu-latest` |
| RNF-04 | Containment | Projectors live in `dare-attack-path`. No engine crate depends on it, and it does not depend on `dare-remote-validation` or `dare-mcp-discovery`. A manifest test forbids `reqwest`, `hyper`, `rmcp` and the `tokio` `net` feature in its `[dependencies]` | Enforced by tests |
| RNF-05 | Explainability | Every node, edge and path traces back to artifact digests and record locators in `projection-report.json` | 100 % |
| RNF-06 | Quality gate | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`, `cargo audit` | All green |

---

## 6. Security requirements

| ID | Requirement | Reference |
|----|-------------|-----------|
| RS-01 | Every artifact, input document and system model is schema-validated, size- and depth-bounded before use, and treated as untrusted | OWASP A03 |
| RS-02 | Labels and ids are validated and escaped (Cycle 008 `validate_safe_label`), with no credential shape in any output, and Cycle 001 redaction is reused | OWASP A02 |
| RS-03 | No URI dereference, no file read outside the supplied paths, no symlink following out of `--artifacts` | OWASP A01 |
| RS-04 | No new dependency with a HIGH/CRITICAL advisory. The path engine is written in-crate; any graph library is justified in the Blueprint | OWASP A06 |
| RS-05 | **No verdict laundering:** a projector cannot turn a non-PASS into PASS, and a path's control state cannot be better than its weakest guard | Cycle 018 aggregation |
| RS-06 | **No silent merge:** identities merge only via the system model (RF-05). This prevents the confused-deputy class of false paths caused by colliding names | Cycle 015 |
| RS-07 | **Analysis only:** the crate cannot execute, send or schedule anything. Handing a path to Cycle 009 remains that cycle's authorized and ROE-bound flow | Product Design §10 |
| RS-08 | **Bounded resource use** against path-explosion DoS (§4.6) | Cycle 008 threats |

---

## 7. Technical stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Rust | edition 2021, MSRV 1.88 |
| Serialization / schema | serde_json, jsonschema | workspace |
| Digests | sha2 | workspace |
| Reused crates | `dare-attack-graph` (model, builder, v1), `dare-security-evidence`, `dare-coverage` (registries), and the engines' public result and input types (`dare-tool-security`, `dare-identity-security`, `dare-memory-security`, `dare-rag-security`, `dare-mcp-auth-security`, `dare-supply-chain-security`, `dare-a2a-security`, `dare-prompt-injection`, `dare-multi-turn-security`) as **library dependencies of the projector crate only**. `dare-remote-validation` is **not** a dependency: its result is read as schema-validated JSON (RF-02) | workspace |
| New dependencies | None expected | — |

---

## 8. External integrations

None. The cycle is offline analysis over local files: no network, no telemetry, and no
model provider.

---

## 9. Constraints

- **Timeline:** one cycle, Design → Blueprint → Review → Execute.
- **Infrastructure:** GitHub Actions only. The PR-open-only trigger is preserved, and a
  new CI job runs ATTACK-PATH-LAB.
- **Technical:**
  - an additive crate;
  - no `unwrap()` in production;
  - engines unchanged (Q3);
  - Cycle 008 v1 output unchanged.
- **Compliance:** lab inputs are synthetic only. Users' system models and artifacts
  stay local; the model can name their real components, so nothing is published.

---

## 10. Out of scope (v1)

- **Blast radius (Cycle 024):** reach and impact from a compromised node, impact
  weighting, "what if this credential leaks".
- **Runtime OpenTelemetry (Cycle 025):** building edges from live traces.
- **Executing or validating paths:** remains Cycles 009 (local, ROE-bound) and 022
  (remote, authorization-bound).
- **Scores:** no risk score, probability, likelihood or CVSS-style number.
- **Automatic entity resolution:** no fuzzy, name- or embedding-based matching, and no
  LLM reasoning.
- **Discovery:** no new discovery of components; only what artifacts and the model state.
- **New property IDs and profile changes:** paths are not properties, so the registry
  and profile denominators stay unchanged.
- **Fleet or enterprise graphs across targets:** one target per run.

---

## 11. Risks and mitigations

| # | Risk | Probability | Impact | Mitigation |
|---|------|-------------|--------|------------|
| R-01 | False paths from merged identities that are not the same entity | Medium | High | Alias-only merging (RF-05, RS-06); lab 024–025 |
| R-02 | `CONTROLS_HELD` read as "secure" | High | High | Unassessed edges force `CONTROL_UNDECIDED` (RF-11); the bounded claim in the summary; O-04 |
| R-03 | Path explosion on real systems | Medium | Medium | Entry → target enumeration only, per-pair and global bounds, reported truncation, chokepoints |
| R-04 | Engine artifacts lack the topology needed (for example 019 does not persist its graph) | High | Medium | Projectors read pinned inputs through the engines' own parsers (Q3); unprojected kinds are reported |
| R-05 | Inconsistent evidence conventions across engines (the property key is `property_id` in five engines and `property` in four; four bridges cite `…/evidence/v1/security-evidence.schema.json`, which does not exist) | Certain | Low | Projectors read both keys through one closed table; the schema-id inconsistency is left to a separate hotfix (Q6) |
| R-06 | v2 changes break Cycle 009/010 consumers | Low | High | v1 kept byte-identical; `Path.status` and `impact_factors` kept (RF-17, O-08) |
| R-07 | The system model becomes an unreviewable blob | Medium | Medium | Closed schema, maxima, a mandatory rationale for declared edges, and `projection-report.json` listing every alias actually used |

---

## 12. Compatibility

Cycle 023 must prove that it:

1. preserves all property IDs and the eleven profile denominators;
2. leaves `validate attack-graph --facts` and every v1 fixture output byte-identical;
3. leaves `dare-adversarial` path eligibility and `dare-continuous` drift unchanged;
4. leaves every engine crate and its artifacts unchanged (Q3);
5. keeps Cycle 001 evidence and redaction contracts and Cycle 018 aggregation;
6. keeps the PR-open-only CI trigger, with no network access and no secrets.

**Completion rule:** every acceptance criterion maps to executed evidence in `PROOF.md`,
and defects are recorded in `REGRESSION.md`.

---

## 13. Open questions for Review

All answered by the Product Owner on 2026-09-28 (the recommended option in each case).

1. **Crate placement — DECIDED:** (a) a new crate, `dare-attack-path`, holding the
   projectors, the system model and path engine v2. `dare-attack-graph` keeps the model,
   the builder and v1. Placing the projectors in `dare-attack-graph` is not buildable:
   the engine crates depend on `dare-adversarial`, which depends on `dare-attack-graph`,
   so it would be a dependency cycle.
2. **Edges from pinned input documents — DECIDED:** (a) `STATICALLY_PROVEN`, citing
   the input digest as the evidence id. Relationships declared only in the system model
   stay `INFERRED` with a mandatory rationale.
3. **019 relationship graph — DECIDED:** (a) the projector re-parses the pinned SBOM
   and manifest inputs through `dare-supply-chain-security`'s public normalization API.
   The engine and its artifacts are unchanged.
4. **Node and edge taxonomy — DECIDED:** (a) the Cycle 008 enums are kept and mapped
   through a closed table. Node provenance records the engine's original kind (for
   example 019 `MODEL`).
5. **Cycle 008 v1 path defects — DECIDED:** (a) items 2–4 of §4.9 are fixed in v2
   only, and v1 output stays byte-identical. Item 1 (`unwrap()`) is fixed in v1 as well,
   without changing output.
6. **Evidence schema id inconsistency — DECIDED:** (b) out of this cycle. It is
   recorded in `BASELINE.md` and handled by a separate hotfix.
7. **Chokepoints — DECIDED:** MUST (RF-12), reported as counts over the enumerated set
   and flagged `partial` when enumeration was truncated.

---

## 14. Approval checklist

- [x] Functional requirements reviewed and prioritized
- [x] "Projectors plus system model, no re-judging" architecture accepted
- [x] Entity resolution by explicit alias only (RF-05) accepted
- [x] Path classification axes (§4.4) and control-state rule (RF-11) accepted
- [x] Entry and target classes (RF-08) and hard maxima (§4.6) accepted
- [x] Schema v2 additive over v1 (§4.7) accepted
- [x] Path-engine defect correction (§4.9) accepted
- [x] Out-of-scope boundary with Cycles 024–025 confirmed
- [x] Critical risks (R-01, R-02) have accepted mitigations
- [x] Open questions in §13 answered — 2026-09-28
