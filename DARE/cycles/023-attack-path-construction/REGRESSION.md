# Cycle 023 — Regression and refinement record

**Status:** IN PROGRESS. This record is completed by task-046.

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

