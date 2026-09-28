# Cycle 023 — Tasks

**Status:** APPROVED FOR EXECUTION  
**Approval:** APPROVED 2026-09-28 — see `APPROVAL.md`  
**Baseline:** `main @ 32909ea`  
**Branch:** `claude/loving-newton-113zme`

Source of truth: `BLUEPRINT.md` (section references below).

A task is DONE only when **both** of these hold:
- its criterion is met by an executed test or command, recorded in
  `EXECUTION/task-NNN.md`;
- the Ralph Loop is green: `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test --workspace`, and `cargo audit` when dependencies change.

Throughout the cycle:
- `dare-attack-path` has no network dependency and never executes anything;
- no engine crate (013–022) changes;
- v1 attack-graph output stays byte-identical.

## Checklist

- [x] task-001 — Record the post-022 baseline, v1 golden digests and observations O-1..O-4
- [x] task-002 — Remove the `unwrap()` from v1 `make_path` and pin v1 output with golden digests
- [x] task-003 — Add the three `schemas/attack-graph/v2` JSON schemas
- [x] task-004 — Implement the `dare_attack_graph::v2` model types
- [x] task-005 — Implement the v2 control-state rule and `validate_graph_v2` invariants 1–7
- [x] task-006 — Implement the v2 Mermaid and DOT renderers
- [x] task-007 — Create the `dare-attack-path` crate skeleton and the containment manifest guard
- [x] task-008 — Implement `limits.rs` and `error.rs`
- [x] task-009 — Implement `admit.rs` file admission and the `sweep.rs` artifact secret sweep
- [x] task-010 — Implement `ids.rs` run-scoped and entity node ids
- [x] task-011 — Add `schemas/attack-path/v1/system-model.schema.json`
- [x] task-012 — Implement `model.rs` system-model admission and resolution rules 1–7
- [x] task-013 — Implement `load.rs` scenario loaders over the engines' public validators
- [x] task-014 — Implement bundle detection and input binding for tool, identity, memory, rag and mcp-auth
- [x] task-015 — Implement input binding for supply-chain and a2a through `StaticAdapter::collect`
- [x] task-016 — Implement bundle handling for prompt-injection, multi-turn and remote
- [x] task-017 — Implement `evidence_index.rs`
- [x] task-018 — Implement `facts.rs` and the `guard_table.rs` verdict rule
- [x] task-019 — Implement the tool projector (§6.1)
- [x] task-020 — Implement the identity projector (§6.2)
- [x] task-021 — Implement the memory projector (§6.3)
- [x] task-022 — Implement the RAG projector (§6.4)
- [x] task-023 — Implement the MCP Auth projector (§6.5)
- [x] task-024 — Implement the supply-chain projector (§6.6)
- [x] task-025 — Implement the A2A projector (§6.7)
- [x] task-026 — Implement the prompt-injection projector (§6.8)
- [x] task-027 — Implement the multi-turn projector (§6.8)
- [x] task-028 — Implement the remote (022) projector (§6.9)
- [ ] task-029 — Implement `merge.rs`
- [ ] task-030 — Implement `designate.rs` default designations and model overrides
- [ ] task-031 — Implement graph construction in `run.rs` and the determinism test
- [ ] task-032 — Implement `continuity.rs` rules C1–C6
- [ ] task-033 — Implement `enumerate.rs` pairwise shortest-first enumeration
- [ ] task-034 — Implement `chokepoint.rs`
- [ ] task-035 — Implement path classification, v2 impact factors and `AttackPathsDoc`
- [ ] task-036 — Add the scale test (O-09)
- [ ] task-037 — Add the `validate attack-paths` CLI subcommand
- [ ] task-038 — Add the refusal corpus (§8.3)
- [ ] task-039 — Build the ATTACK-PATH-LAB harness and scenarios APL-001..APL-012
- [ ] task-040 — Add scenarios APL-013..APL-026 and the class-contract test
- [ ] task-041 — Add the `attack-path-2026` CI job
- [ ] task-042 — Read a v2 graph in `dare-product` (RF-16, BQ-3 (a))
- [ ] task-043 — Add compatibility tests (§8.4)
- [ ] task-044 — Security, dependency and container audit
- [ ] task-045 — Write the EN/PT attack-path pages and the system-model reference
- [ ] task-046 — Write REGRESSION.md and PROOF.md, run the completion gate and create the cycle archive branch

## Task table

| ID | Title | Phase | Depends on | Complexity | DONE criterion |
|---|---|---|---|---|---|
| task-001 | Record the post-022 baseline, v1 golden digests and observations O-1..O-4 | 0 — Baseline | — | LOW | `BASELINE.md` records: `32909ea`; the `cargo test --workspace` suite and pass counts; 22 workspace members; the 11 pinned profile denominators; the registry digests; the SHA-256 of `attack-graph.json` and `paths.json` produced by `validate attack-graph --facts` for each of the 5 `fixtures/attack-graph/*.json`; observations O-1..O-4 with file:line. It also records either a builder-stage `docker build` or the last green `action-e2e.yml` run on `main` |
| task-002 | Remove the `unwrap()` from v1 `make_path` and pin v1 output with golden digests | 1 — v1 and v2 contract | task-001 | LOW | `crates/dare-attack-graph/src/path.rs` has no `unwrap`/`expect` outside `#[cfg(test)]`, and a missing edge gives `GraphError::Invalid` (BLUEPRINT §4.10). `tests/v1_unchanged.rs` asserts the task-001 digests for all 5 fixtures. The existing `dare-adversarial` and `dare-continuous` tests pass unchanged |
| task-003 | Add the three `schemas/attack-graph/v2` JSON schemas | 1 — v1 and v2 contract | task-001 | MED | `attack-graph.schema.json`, `attack-paths.schema.json` and `projection-report.schema.json` compile under draft 2020-12 and use `additionalProperties: false` throughout. Their fields and enums match BLUEPRINT §4.7–§4.8. Entry and target classes are separate enums |
| task-004 | Implement the `dare_attack_graph::v2` model types | 1 — v1 and v2 contract | task-003 | MED | Every type in BLUEPRINT §4.7 exists with `deny_unknown_fields`. A serde round-trip of a hand-built golden example validates against the schema. `ImpactFactorsV2` flattens the v1 factors. No v1 type or v1 serialization changes (task-002 test still passes) |
| task-005 | Implement the v2 control-state rule and `validate_graph_v2` invariants 1–7 | 1 — v1 and v2 contract | task-004 | HIGH | `v2::control::path_control_state` implements BLUEPRINT §7.4, including the BQ-1 exemption. An exhaustive test over up to 4 edges × {PASS, FAIL, INCONCLUSIVE, ERROR, no guard} proves the result is never better than the weakest edge. `validate_graph_v2` rejects each invariant violation of §4.7, with one test per invariant; invariant 6 includes a doctored `control_state` |
| task-006 | Implement the v2 Mermaid and DOT renderers | 1 — v1 and v2 contract | task-004 | LOW | `to_mermaid_v2` and `to_dot_v2` label evidence state and control state in text, not colour alone, and escape labels exactly as v1 does. A hostile-label test (`"]; click`, `-->`, `<script>`) renders escaped output |
| task-007 | Create the `dare-attack-path` crate skeleton and the containment manifest guard | 2 — Skeleton | task-001 | LOW | The crate is a workspace member with the dependencies of BLUEPRINT §2 only. `tests/manifest.rs` checks two things: `[dependencies]` contains none of `reqwest`, `hyper`, `rmcp`, `tokio`, `axum`, `dare-remote-validation` or `dare-mcp-discovery`; and no `crates/*/Cargo.toml` other than the CLI (and `dare-product` only if BQ-3 were (b)) depends on it. A source scan finds no `std::net` or `std::process` in `src/` |
| task-008 | Implement `limits.rs` and `error.rs` | 2 — Skeleton | task-007 | LOW | Constants equal BLUEPRINT §4.2. `ConstructOptions` validation refuses 0 and values above each maximum (`BoundAboveMaximum`), with one test per bound. Every `Refusal` and `ModelRefusal` variant of §4.1 exists, and `no_error_message_echoes_input` passes |
| task-009 | Implement `admit.rs` file admission and the `sweep.rs` artifact secret sweep | 2 — Skeleton | task-008 | MED | Admission refuses the following, and each has a test: a symlink (`Symlink`), a path escaping the directory (`PathEscape`), 16 MiB + 1 byte (`FileTooLarge`), and JSON depth 65 (`TooDeep`). The sweep refuses each AD-12 marker and a `bearer ` credential, and accepts the lab fixtures |
| task-010 | Implement `ids.rs` run-scoped and entity node ids | 2 — Skeleton | task-008 | LOW | `local_token`, `scoped_node_id`, `entity_node_id` and `display_name` follow BLUEPRINT §4.3. The `x-` hashing path is tested with a `:`, a space, a bidi character and a credential-shaped id. Every produced id matches the v1 node-id pattern. `RunTag` is the first 12 hex digits of the SHA-256 of the result bytes |
| task-011 | Add `schemas/attack-path/v1/system-model.schema.json` | 3 — System model | task-007 | MED | The schema compiles, uses `additionalProperties: false`, and matches BLUEPRINT §4.5 field for field, including the id patterns, the `run` pattern `^[0-9a-f]{12}$`, "exactly one of `entity_id`/`node_id`" in `Designation`, and the §4.2 array limits |
| task-012 | Implement `model.rs` system-model admission and resolution rules 1–7 | 3 — System model | task-009, task-010, task-011 | MED | Each rule of BLUEPRINT §4.5 has a test asserting its `ModelRefusal` variant. The tested cases include a conflicting alias, an unknown entity, a type clash, a duplicate entity, a declared edge without a rationale or reason, and an entity id containing `:`. Unused aliases are reported, not refused. `model_digest` is the canonical digest of the admitted model |
| task-013 | Implement `load.rs` scenario loaders over the engines' public validators | 4 — Bundle | task-009 | MED | For tool, identity, memory, rag, mcp-auth, supply-chain and a2a, the loader runs the sequence of BLUEPRINT AD-04 using only `pub` engine items. A parity test proves that, for every scenario file in the engines' existing test fixtures, the loaded scenario hashes to the digest the engine's own `bind` computes |
| task-014 | Implement bundle detection and input binding for tool, identity, memory, rag and mcp-auth | 4 — Bundle | task-013 | MED | Detection refuses zero or several result files (`UnknownBundle`) and duplicate result bytes (`DuplicateRun`). Each of the five BLUEPRINT §4.4 rows has a passing bundle test and a one-field-edited mismatch test (`DigestMismatch`) and a missing-input test (`MissingInput`) |
| task-015 | Implement input binding for supply-chain and a2a through `StaticAdapter::collect` | 4 — Bundle | task-013 | HIGH | Both rows of BLUEPRINT §4.4 pass, including built-in corpus ids (rule 1) and replay captures (rule 2). A one-byte change to a BOM, a delegation file or the 019 manifest is refused (`DigestMismatch`), and the `collect` output digest equals `result.evidence_digest` on the engines' fixtures |
| task-016 | Implement bundle handling for prompt-injection, multi-turn and remote | 4 — Bundle | task-013 | MED | Checks are per engine: prompt-injection is accepted result-only; multi-turn: the `final_chain_digest` check against `multi-turn-conversations.json` passes, and fails after a one-byte change; remote: `remote-result.json` validates against the embedded 022 schema, and an optional `inputs/run-<i>/scenario.json` must match `runs[i].scenario_digest` |
| task-017 | Implement `evidence_index.rs` | 4 — Bundle | task-009 | MED | Every record is validated with `dare_security_evidence::validate` (`InvalidEvidence` on failure). The property key is read through the closed `property_id`/`property` table for all 9 engine namespaces. Every id in `result.evidence_ids` must be present (`UnknownEvidenceId`). Records are indexed by id and by property |
| task-018 | Implement `facts.rs` and the `guard_table.rs` verdict rule | 5 — Projectors | task-010, task-017 | HIGH | `RunFacts` and the related types match BLUEPRINT §4.6. The §6.11 rule is implemented and tested: RUN scope; ENTITY-scope narrowing, where FAIL on named endpoints gives INCONCLUSIVE on other guarded edges; FAIL without a named entity. A test asserts that every property id named in §6.1–§6.9 exists in `REGISTRY_JSON` or `AGENTIC_REGISTRY_JSON` |
| task-019 | Implement the tool projector (§6.1) | 5 — Projectors | task-014, task-018 | MED | One test per table row and per guard mapping. Destructive and sensitive flags follow the table. `ToolViolation.tool_id` narrows FAIL. Unlisted event kinds are counted in `unprojected` |
| task-020 | Implement the identity projector (§6.2) | 5 — Projectors | task-014, task-018 | HIGH | One test per table row. The principal kind → node type mapping is complete. `DELEGATES_TO` is OBSERVED when a matching `DelegationEdge` event exists and STATICALLY_PROVEN otherwise. `authority_mutation` is set exactly when `AUTHORIZATION_EXECUTION_BINDING` or `PRINCIPAL_BINDING` is FAIL. The SUT is `agent_principal_id` |
| task-021 | Implement the memory projector (§6.3) | 5 — Projectors | task-014, task-018 | MED | One test per table row. Item `TRANSFERS_TO` tool appears only when influence on tool selection or tool argument and a performed action are in the **same** trial. `READS` and `TRANSFERS_TO` carry their separate guard sets |
| task-022 | Implement the RAG projector (§6.4) | 5 — Projectors | task-014, task-018 | MED | One test per table row. `READS` carries the access guards and `TRANSFERS_TO` the content-trust guards. `sensitive` is set for `CONFIDENTIAL` and `RESTRICTED`. Collections appear only in provenance |
| task-023 | Implement the MCP Auth projector (§6.5) | 6 — Projectors | task-014, task-018 | MED | One test per table row. An upstream credential is `privileged`. `authority_mutation` compares authorized and performed principal, tenant and resource. Every guard is RUN scope |
| task-024 | Implement the supply-chain projector (§6.6) | 6 — Projectors | task-015, task-018 | MED | The `ComponentType` and `RelationType` tables are exhaustive: a test iterates every enum variant. Dependency edges point from dependency to dependent. `PROVIDED_BY`, `ATTESTED_BY` and `SIGNED_BY` are counted, not projected. Each edge cites DOC(d) or IN |
| task-025 | Implement the A2A projector (§6.7) | 6 — Projectors | task-015, task-018 | MED | One test per table row. Peers are `AGENT` nodes and each exchange is peer `CALLS` SUT, with authority from `authorization_subject()`. `AUTHORITY_PROPAGATION` guards only `DELEGATES_TO`, and the other 11 `AGENT.A2A.*` properties guard `CALLS`. `card_for` is not called |
| task-026 | Implement the prompt-injection projector (§6.8) | 7 — Projectors | task-016, task-018 | LOW | The channel node is named from `source_kind`. Designation follows `direction`. A `StructuredActionRequest` gives SUT `CAN_INVOKE` tool. `result.property_id` guards the channel edge |
| task-027 | Implement the multi-turn projector (§6.8) | 7 — Projectors | task-016, task-018 | MED | One channel node per role in {USER, TOOL, RETRIEVED, MEMORY}, and `APPROVAL` is not an entry. Each `DelegatedFinding` adds an ENTITY-scope FAIL on the channel edge of its turn's role. Executed actions give `CALLS` and requested ones give `CAN_INVOKE` |
| task-028 | Implement the remote (022) projector (§6.9) | 7 — Projectors | task-016, task-023, task-025, task-026, task-027 | MED | Each run's `engine_result` is decoded as the owning engine's result type and projected result-only. `runs[i].verdict`, not `engine_verdict`, is the guard verdict. A multi-turn run is counted `MULTI_TURN_RESULT_ONLY`. Every fact has `dynamic_authorized: true`. The 022 CLI's own test fixtures are used as input |
| task-029 | Implement `merge.rs` | 8 — Graph | task-012, task-019, task-020, task-021, task-022, task-024, task-028 | HIGH | BLUEPRINT §7.1 steps 1–7 and the §4.9 edge-merge rule each have a test. Two runs of the same engine with the same local id stay separate without an alias, and merge with one. A tenant disagreement on a merged node is refused. Authority fields are rewritten to node ids or `ext:` |
| task-030 | Implement `designate.rs` default designations and model overrides | 8 — Graph | task-029 | MED | Every row of BLUEPRINT §6.10 has a test. `CROSS_TENANT_RESOURCE` is computed per entry. Model additions and `exclude` removals apply after the defaults. A designation of an unknown node is refused |
| task-031 | Implement graph construction in `run.rs` and the determinism test | 8 — Graph | task-005, task-030 | MED | `construct` builds an `AttackGraphV2` that passes `validate_graph_v2`. Ten runs over shuffled artifact order give byte-identical `attack-graph.json`. No wall-clock value appears in any output |
| task-032 | Implement `continuity.rs` rules C1–C6 | 9 — Path engine | task-031 | HIGH | Each of the rules C1–C6 of BLUEPRINT §7.3 has a positive and a negative test. `discontinuity_at` names the first failing edge. The C4 rule requires both `authority_mutation` and a FAIL guard from the named property list |
| task-033 | Implement `enumerate.rs` pairwise shortest-first enumeration | 9 — Path engine | task-031 | HIGH | The BLUEPRINT §7.2 algorithm is implemented. Tests cover: shortest-first ordering; the per-pair cap, with a truncation record; `MAX_PATHS`; `MAX_STEPS` on K₁₂; cycles and self-loops; path ids equal the v1 formula; ids that do not depend on input order. There is no O(n) scan per step |
| task-034 | Implement `chokepoint.rs` | 9 — Path engine | task-005, task-033 | MED | BLUEPRINT §7.5 is implemented. Tests cover a single path, disjoint paths (no chokepoint), a shared edge, BQ-1-exempt edges excluded, and `partial` set on truncation |
| task-035 | Implement path classification, v2 impact factors and `AttackPathsDoc` | 9 — Path engine | task-032, task-033, task-034 | MED | Every path carries feasibility, control state, `failed_guards`, `undecided_edges`, entry and target and their classes, and `ImpactFactorsV2`. Discontinuous paths go to their own list. The six v1 impact factors equal v1's on the 5 v1 fixtures. `AttackPathsDoc` validates against its schema |
| task-036 | Add the scale test (O-09) | 9 — Path engine | task-035 | LOW | `tests/scale.rs` builds a fixed-seed synthetic graph of 2 000 nodes, 10 000 edges and 50×50 pairs, and constructs and enumerates it in < 10 s with `--release`. No bound is exceeded |
| task-037 | Add the `validate attack-paths` CLI subcommand | 10 — CLI and lab | task-006, task-035 | MED | The flags match BLUEPRINT §5.1. The six files are written in the stated order, each validated and swept first. Exit codes 0, 1, 2 and 3 are each tested. Nothing is written on refusal. `--help` offers no URL, shell or engine-command flag. `validate attack-graph --facts` is unchanged |
| task-038 | Add the refusal corpus (§8.3) | 10 — CLI and lab | task-037 | MED | Every item of BLUEPRINT §8.3 is a test that asserts exit 3, zero files written, and an error text containing no input value |
| task-039 | Build the ATTACK-PATH-LAB harness and scenarios APL-001..APL-012 | 10 — CLI and lab | task-037 | HIGH | The harness runs each engine through the real binary, copies the inputs, runs `validate attack-paths`, and compares with `expected.json` (BLUEPRINT §8.1). No hand-written graph facts are used. APL-001..012 and their control and NOT_TESTED twins pass |
| task-040 | Add scenarios APL-013..APL-026 and the class-contract test | 10 — CLI and lab | task-039 | HIGH | The scenarios APL-013..026 pass. The class contract holds: every class has a control twin; every `CONTROL_FAILED` expectation names its property; every scenario's double run is byte-identical. APL-022..023 give `DISCONTINUOUS`, APL-024..025 prove alias-only merging, and APL-026 carries `dynamic_authorized` |
| task-041 | Add the `attack-path-2026` CI job | 11 — CI and product | task-036, task-038, task-040 | LOW | The job runs the lab, the refusal corpus and `scale.rs` in release. It keeps the PR-open trigger and references no `secrets.*` and no network target, which a test reading `ci.yml` asserts. It runs locally through `scripts/run-ci-job-locally.py` |
| task-042 | Read a v2 graph in `dare-product` (RF-16, BQ-3 (a)) | 11 — CI and product | task-005 | MED | A product fixture may name `attack_graph_v2: <path>`. The product then reads the file, validates it with `dare_attack_graph::v2` only, and writes it as the run's `attack-graph.json`. Without the field, output is byte-identical to before. `dare-product` does not depend on `dare-attack-path` |
| task-043 | Add compatibility tests (§8.4) | 12 — Audit | task-037, task-042 | MED | The tests cover: v1 golden digests hold; `ensure_path_eligible` behaves identically for a v2 path and the v1 path with the same id; `dare-continuous` drift tests pass; registry and profile digests are unchanged; the engine crates' diffs are empty; every `include_str!` lies under a Docker-copied directory |
| task-044 | Security, dependency and container audit | 12 — Audit | task-041, task-043 | MED | The audit passes on four checks: `cargo audit` is clean; `scripts/k23/assert_no_real_credentials.py` (following `scripts/k22/`) is clean over the lab fixtures; the builder-stage image builds; the in-image binary exits 3 on `validate attack-paths` with a tampered bundle, with networking disabled |
| task-045 | Write the EN/PT attack-path pages and the system-model reference | 13 — Docs and proof | task-037 | LOW | The concept page (EN and PT) and the EN system-model reference are added and linked in both `SUMMARY.md` files. They state that `CONTROLS_HELD` is not "secure" and that paths beyond `max_path_edges` are not covered. Both mdBook builds are green |
| task-046 | Write REGRESSION.md and PROOF.md, run the completion gate and create the cycle archive branch | 13 — Docs and proof | task-044, task-045 | MED | Every Design acceptance item and objective O-01..O-09 maps to an executed test in `PROOF.md`. `scripts/k23/verify_proof_citations.py` passes. The full completion gate is green. `agent/cycle-023-attack-path-construction` is pushed at the final cycle commit |

## Notes on the Blueprint

- **task-005** places the control-state function in `dare_attack_graph::v2`, not in
  `dare-attack-path/src/control.rs` (BLUEPRINT §3). `validate_graph_v2`, whose invariant
  6 recomputes the state, lives in `dare-attack-graph`. Keeping the rule there avoids a
  second copy. `dare-attack-path` calls it, and the behaviour and tests are unchanged.
- **Phase 1 (task-002 to task-006)** does not wait for the new crate. It touches only
  `dare-attack-graph`, as BLUEPRINT §9 states.
