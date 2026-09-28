# Cycle 023 — Regression and refinement record

**Status:** COMPLETE (task-046).

## Blueprint refinements made during execution

Each entry fixes a rule the Blueprint stated in a form the engines' actual behaviour
could not satisfy. None crosses a frozen boundary in `APPROVAL.md`:
- no engine crate changes;
- v1 output is unchanged;
- no verdict is re-decided;
- no identity is merged without an alias.

| # | Blueprint text | What the code does, and why | Task |
|---|---|---|---|
| R-1 | §4.7 lists all invariants under `validate_graph_v2` | Path invariants run in `validate_paths_v2(graph, doc)`, because paths live in `attack-paths.json`. The rules are unchanged | 005 |
| R-2 | AD-06 / §4.4 rule 2: 019/020 evidence is rebuilt through `StaticAdapter`, or a capture is compared by its own digest | Evidence is rebuilt with **the adapter the engine used**, chosen by `result.mode`: static, replay (capture plus the local manifest or policy, which the replay digest includes), simulated, or local-synthetic. Each ends in the same `evidence_digest` comparison | 015 |
| R-3 | §4.4 rule 5 reads every evidence file as an array | Multi-turn writes `{schema_version, records, coverage}`. The index reads `records` for that engine only | 017 |
| R-4 | §6.1 / §6.2 / §6.3: `dispatched: true` / `performed: true` gives CALLS | In Cycles 013–016 these flags are **structurally false**: those engines observe requests and never perform them. An observed request is projected as the relationship a deployment would exercise, with OBSERVED evidence and `original_kind` "… (request, not execution)". Taken literally, the Blueprint rule could never fire. 021, which reports executions, keeps CALLS versus CAN_INVOKE | 019–021, 026 |
| R-5 | §6.2 leaves effective principal `USES_CREDENTIAL` unguarded | The engine's `CREDENTIAL_CONTEXT_NOT_EXPAND_AUTHORITY` invariant belongs to the Privilege class, so `AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION` guards that edge (role `IdentityUsesCredential`) | 018, 020 |
| R-6 | §6.6 cites the BOM "when a BOM stated it", worded around `evidence_source` | When the manifest agrees with a BOM edge, the engine merges it with `evidence_source = DARE_MANIFEST`. The projector therefore uses `observation != DECLARED` to decide that a BOM stated the edge | 024 |
| R-7 | §6.11: RUN verdict "`result.verdict` of per-trial engines" | The guard verdict for property P is the Cycle 018 aggregate over **the run's evidence records for P**. For single-property engines this equals the result verdict. For 019, 020 and 021 it aggregates the invariants that map to the same property. For 022 the records carry the verdict after the transport overlay | 018 |
| R-8 | AD-08: the SUT of 016/017 is "the acting principal" | Implemented as stated. The node takes the acting principal's declared kind (for 017, AGENT when the context lists no kind), not the literal `sut`, so it can be aliased like any principal | 021, 022 |
| R-9 | §6.10: the tenant of an entry that has none is taken from "the first tenant-bearing edge authority on the path" | That tenant depends on a path that does not exist yet when pairs are formed. An entry with no tenant therefore gets no `CROSS_TENANT_RESOURCE` pairs. A path that crosses tenants is still flagged by its `cross_tenant` impact factor | 030 |
| R-10 | AD-10: paths within a length level are ordered by `path.id` | Paths within a level follow depth-first order over adjacency sorted by (next node id, edge id). This order is equally deterministic and independent of input order (tested), and the search stops at the cap + 1. Sorting by hash would require holding every path of a level in memory first | 033 |
| R-11 | §7.2: pairs are keyed by (entry, target, target class) | Pairs are keyed by (entry node, target node) and carry the lowest entry and target class in enum order. Two classes of the same node pair would otherwise enumerate the same path twice, with the same id | 035 |
| R-12 | §7.3 C3: the edge's `authority.principal` must be in A ∪ {P} | A principal written `ext:<token>` is a subject that is not a graph node, such as the user a peer acts for. Continuity cannot check it, so it never breaks a path. Without this, every A2A path would be DISCONTINUOUS | 032 |
| R-13 | §4.3: the unsafe-label fallback is `<type-slug> <token>` | The fallback is always `<type-slug> x-<32 hex>`. The Cycle 008 label check refuses any text that contains `sk-` (as in "support-de**sk-**tools"), so reusing the raw token could fail the same check again | 010, 031 |
| R-14 | v2 schema: guard property pattern `[A-Z_]` | The pattern is `[A-Z0-9_]`, because `AGENT.A2A.*` contains a digit. Found by the first end-to-end build | 031 |
| R-15 | `artifact_index` is the position of `--artifacts` | Refusals still name the position the user gave. After loading, the graph re-indexes artifacts in result-digest order, so the same artifacts in any order give byte-identical output (O-06) | 031 |
| R-16 | §8.1: the lab runs REPLAY traces (013–018, 021) or STATIC evidence (019, 020) written for each chain | The lab runs **the engines' own shipped LAB scenarios** in their default mode (simulated; static for the 019 BOMs) and the 022 replay fixture. These are the inputs each engine's own tests pin. New traces would be more hand-written engine input with no added meaning, and the evidence still comes from the real binary. Nodes that no alias names are referred to as `${run:N}` (the run tag of run N) | 039 |
| R-17 | §8.1 table: chains per class (017→014→015, 019 `EXPOSES_TOOL`, …) | Each class is built from the relations the engines actually emit (`crates/dare-agent-security-cli/tests/fixtures/attack-path-lab/README.md`). A: no engine emits a tool → resource edge, so the chain is document → acting principal → cross-tenant document or privileged credential. D: no 019 input yields `EXPOSES_TOOL`: the CycloneDX importer maps dependencies only, SPDX has no such relation, and the built-in corpus has none. The build is joined to the assistant by one declared `TRANSFERS_TO` (INFERRED), which leaves the path UNDECIDED at best. E: the 018 chain runs inbound token → MCP server → upstream credential → resource, which is the passthrough chain. F: 013 and 021 reach the destructive tool without 014. `mcp-auth` uses one local id (`mcp-invoices`) for an MCP server and a resource, so that id cannot be aliased (TYPE_CLASH), and its nodes stay run-scoped | 039, 040 |
| R-18 | §8.1 APL-026: "a remote (022) A2A run joined to a 015 run" | The 022 CLI test data holds a MULTI_TURN run, not an A2A one. It is projected result-only (`MULTI_TURN_RESULT_ONLY`) and still carries `dynamic_authorized` provenance, which is what APL-026 asserts. An A2A capture would need a new REMOTE-LAB fixture generator in the 022 crate's tests, which is an engine crate this cycle does not change | 040 |
| R-19 | §8.1 APL-022..023: unexplained authority change from 015 and 014 facts | No engine emits an edge whose named principal is another graph node. Identity, memory, RAG and MCP Auth name the edge's own source, tool emits no principal, and A2A subjects are opaque (`ext:`, R-12). An unexplained authority change therefore cannot come from engine facts alone. APL-022..023 state one with a declared `CAN_REACH` (INFERRED) made under a principal the path never acquired, and C3 rejects it at that edge. Continuity is unchanged | 040 |

## Path-engine defect correction (DESIGN §4.9, Q5)

| Defect | v1 (`validate attack-graph`) | v2 (`validate attack-paths`) |
|---|---|---|
| 1. `unwrap()` in `make_path` | **Fixed without changing output.** A missing edge is `GraphError::Invalid` (`a_path_naming_a_missing_edge_is_an_error_not_a_panic`). The five golden digests hold (`v1_output_is_byte_identical_to_the_baseline`) | not applicable: new engine, and no `unwrap` in production code |
| 2. Silent truncation | Kept (Q5), so Cycle 009/010 artifacts do not change | Every bound that stops the search is reported: `truncated`, `stopped_by`, pairs truncated (`the_per_pair_cap_is_reported_and_keeps_the_shortest`, `the_global_cap_and_the_step_bound_are_reported`) |
| 3. Sink-only emission | Kept (Q5) | Paths are enumerated per (entry, target) pair and end at the target, whatever its out-degree (`paths_are_shortest_first_simple_and_validated`) |
| 4. O(n) lookups per step | Kept (Q5) | Adjacency is indexed once; 2,000 nodes and 10,000 edges run in about 0.6 s in release (`a_two_thousand_node_graph_is_built_and_enumerated_within_bounds`) |

## Baseline observations O-1..O-4 (BLUEPRINT §13, Q6)

These are recorded for a separate hotfix. None was changed in this cycle, because each
lies in an engine crate, which is a frozen boundary.
`the_engine_crates_are_unchanged` proves the engine trees equal `32909ea`.

| # | How Cycle 023 lives with it |
|---|---|
| O-1 | The evidence index reads records with `dare_security_evidence::validate`, and does not dereference the cited schema id |
| O-2 | The A2A projector never calls `card_for`. Peers are keyed by their own ids (task-025) |
| O-3 | Manifest, provenance and attestation files are bound through the rebuilt `evidence_digest` (AD-06, R-2). A one-byte change is refused (`a_changed_manifest_changes_the_rebuilt_evidence_and_is_refused`) |
| O-4 | The tool projector binds through the scenario digest and evidence ids, and does not index events by `event_digests[i]` |

## Frozen boundaries (APPROVAL.md)

| Boundary | Held by |
|---|---|
| No engine crate (013–022) changed | `the_engine_crates_are_unchanged` (tree digests against `32909ea`) |
| v1 attack-graph output byte-identical | `v1_output_is_byte_identical_to_the_baseline`; `a_v2_path_is_eligible_exactly_when_the_v1_path_with_its_id_is` |
| No merge without an explicit alias | `the_same_local_id_in_two_runs_stays_two_nodes_without_an_alias`; ATTACK-PATH-LAB APL-024..025 |
| Control state never better than the weakest guard | `the_state_is_never_better_than_the_weakest_edge`; `invariant_6_a_doctored_control_state_is_refused` |
| No network dependency in `dare-attack-path` | `no_network_process_or_scheduler_dependency_is_declared`, `the_source_reaches_no_socket_process_or_thread_pool` |
| No scores | Chokepoints are counts (`chokepoints_are_the_edges_every_failed_path_shares`); the v2 schemas carry no score field |
| No property or profile change | `the_registries_and_every_profile_are_unchanged` |

No task crossed a boundary, so no stop was needed for Review. The refinements above
(R-1..R-19) change how a Blueprint rule is realized, never a verdict, a digest or an
identity rule.

## Notes for the next cycle

- **A2A subjects are opaque.** The A2A projector names the peer's authorization subject
  as the edge principal. That subject is never a graph node, so it becomes `ext:` and
  never breaks continuity (R-12). An A2A path therefore cannot be `DISCONTINUOUS`
  because of the subject it acts for. Checking that subject against a delegation chain
  would need a continuity rule for delegated subjects (C1 hands authority to the
  delegatee and does not remember the delegator), which would change verdict semantics
  and needs Review.
- **No engine emits a tool → resource or `EXPOSES_TOOL` edge** that the lab could use
  (R-17). A projector for tool effects, or a 019 importer for exposed tools, would let
  classes A and D be built from engine facts alone.
- **An A2A remote fixture** for the 022 CLI data would let APL-026 carry a projected
  remote run, not only its provenance (R-18).

