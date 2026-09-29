# Cycle 024 — Regression and refinement record

**Status:** COMPLETE. Seven refinements (R-1..R-7). None crosses a frozen boundary. R-6's open decision was resolved at Review (2026-09-29).

## Blueprint refinements made during execution

Each entry fixes a rule the Blueprint stated in a form the actual behaviour of the code
could not satisfy. None crosses a frozen boundary in `APPROVAL.md`.

| # | Blueprint text | What the code does, and why | Task |
|---|---|---|---|
| R-1 | §7.3 / task-001: the goldens are the SHA-256 of the six outputs of each ATTACK-PATH-LAB scenario, run fresh through the engines | The engines stamp evidence with the wall clock, and the prompt-injection, multi-turn and static supply-chain results differ between runs. A fresh run's outputs are therefore stable within one run (the lab's double run) but not across runs. The goldens run `validate attack-paths` over a frozen snapshot of the 35 unique engine runs, taken at the baseline before any code change (`tests/fixtures/attack-path-lab-frozen/`, 2.3 MB). They pin the same 156 files. The fresh lab still runs in CI, so the snapshot cannot drift from what the engines emit without the lab noticing | 001, 002 |
| R-2 | §6.3: a step is attempted only when `e.target` is not on the parent chain (simple routes), with `visited` keyed by `(node, authority)` | Together, these two rules can lose an uncontained route. A state first reached through a chain containing X blocks every later chain to the same state, and that chain then refuses to pass X again. A target could be reported `CONTAINED` while an uncontained route exists, which breaks O-03 and the frozen containment boundary. The search is therefore over **walks**: no parent-chain check, `visited` keyed by `(node, authority)`. Every state reachable within `max_depth` is found at its least depth. A walk re-enters a node only under a different authority, so it terminates. Witness routes are shortest walks, and a node repeats in one only when the authority differs (`walks_revisit_a_node_only_under_new_authority_and_cycles_terminate`) | 011 |
| R-3 | DESIGN §4.2: `COMPONENT_COMPROMISE` means the component "acts under whatever authority its edges carry" | The component starts with P unset and A = {seed}. The continuity rule is unchanged (frozen), so C3 refuses an access that names a principal the walk never acquired, even from a compromised component; the step is counted in `refused_steps`. The component goes on through unnamed accesses, credentials (C2) and delegations (C1) (`a_component_continues_through_unnamed_access_credentials_and_delegation`). The wording in the concept page follows this | 011 |

| R-4 | §4.5 inv. 8: "Totals and counts equal the recomputation from `seeds`. The top-level `truncated` is the OR of every search"; §4.4: "`truncated`: any search truncated, or the total budget ran out" | `tenants_reached` covers every reached node, and the document lists only the target routes. It therefore cannot be recomputed from the document. The validator checks two things: it is a superset of the tenants on the view's routes, and it never contains the seed's tenant. Everything else in impact, totals and the frontier is recomputed exactly. §4.4 and §4.5 disagree when the remediation delta exhausts the shared budget. The code follows §4.4: `truncated` is the OR of every search, or a delta that ran out of budget. In that case `stopped_by` carries `MAX_STATES_TOTAL` and a partial delta entry exists, and the validator requires both | 016, 017 |
| R-5 | §6.8 / task-017: "shuffles the graph's `nodes` and `edges` arrays 10 times" through `analyze` | A graph file must list nodes and edges sorted to pass `validate_graph_v2`, which is Cycle 023's contract and is not changed. A shuffled file is refused as `InvalidGraph`, and a test covers that. The shuffles therefore go to `analyze_graph`, the step after admission. They cover nodes, edges, targets and seeds, and the graph id is re-sealed. The documents are equal after the graph id is mapped | 017 |
| R-6 | O-08 / task-018: "a fixed-seed graph of 2 000 nodes, 10 000 edges and 64 seeds … in under 10 s with `--release`" | **Why the state space is so large.** C3 adds every node an access reaches to the actor set `A`. On a dense graph, almost every walk therefore carries a distinct authority, and any graph of this size runs into the 5 000 000-state total budget. The time is then the throughput at the budget ceiling. **Changes (search only):** authorities are stored once in the arena; a fast fingerprint chain, confirmed by equality, replaces the `(node, Authority)` hash set; a refused step reuses its copy. This took the budget-bound run from 37 s to about 9 s. The rule is still called only through `Authority::step`. **Tests:** `tests/scale.rs` has two graphs. A **lab-shaped** layered graph must finish in under 10 s; it measured 8.4–9.2 s here. A **uniform** random graph checks that no bound is overshot and that truncation is reported (`CONTAINMENT_UNKNOWN`, partial delta); its time, 9.3–10.2 s here, is printed but not asserted, because it measures the ceiling itself. **Margin is thin, open for Review.** The remaining cost is allocation of the `String`-based `Authority`. Two faster options each cross an approved rule, so neither was taken. (a) Deterministic speculative threads (`EXECUTION/task-018-parallel-option.patch`, which measured 7.3 s / 3.4 s) need an RS-08 amendment. (b) A compact `Authority` representation touches the moved continuity module | 018 |
| R-7 | §7.1 BRL table: rows are mapped to APL graphs and classes | The expectations were written from the APL graphs before any BRL run. Where a row's wording did not fit the graph the APL scenario actually builds, the row was adapted as follows, and the class contract still holds. **BRL-003/004:** in APL-001/002 the index-admin credential reaches only `document-123`, which is not a target. BRL-003 therefore keeps the credential-leak seed with `document-123` listed as absent (not a target, so not reported), and adds alice's takeover (credential via `PRIVILEGE_AMPLIFICATION`, tenant-B document via `TENANT_DOCUMENT_ISOLATION`). BRL-004 is its control. **BRL-002/016:** BRL-001 seeds both the token and alice. BRL-002 is alice's control and BRL-016 is the token's control twin: its two `CONTAINED` targets equal what BRL-001's credential-separation delta counts for the token. **BRL-006/013:** the APL-010/014 controls remove the failing guard but leave inconclusive ones, so the target stays `EXPOSED` / `CONTROL_UNDECIDED`, not `CONTAINED`. The lab asserts exactly that. **BRL-018:** in APL-023 the peer also reaches the ticket through the credential, so the scenario sets `max_depth: 2`: the refused access is counted and the target is absent within the bound. **BRL-020** uses APL-006 instead of APL-005. In APL-005 every guard on alice's route fails, so a truncated search still finds the credential `EXPOSED`. In APL-006 every guard holds, so three states truncate the uncontained search first and give `CONTAINMENT_UNKNOWN`. **Classes** H (continuity), I (entry-point mode) and J (bounds) carry no attack role, so the contract requires no twin | 023, 024 |

## Regression result

- The Cycle 023 output is byte-identical: 156 golden digests over the frozen runs, and
  `attack_path_lab.rs`, `attack_paths_cli.rs` and `attack_path_compatibility.rs` are
  green.
- No engine crate changed, and no registry or profile changed.
- The full workspace passes: 347 suites, 4 433 passed, 0 failed, 9 ignored (PROOF §8).

## R-6 decision (Review, 2026-09-29)

The Product Owner chose option (c). O-08's 10 s stays the target for the layered graph
and is measured on every run. The test reports a run above the target and fails only
above a 20 s ceiling: twice the target, and still below the 37 s of the search before
the R-6 optimisations. So a slow or loaded runner is no longer read as a defect, but a
real regression still fails. Option (a) (threads, needs an RS-08 amendment) is
declined. Option (b) (a compact `Authority`) is deferred to a later performance cycle.
The change is confined to `tests/scale.rs`; no `src/` file changes. Measured after the change on the same container, in release: layered 14.6 s (reported over the target, passes), uniform 12.6 s. The old assertion would have failed that run with no code defect.

## R-6 follow-up (2026-09-29): option (b) done

The deferred option (b), a compact `Authority`, was implemented as Cycle 025 R-13.
The continuity rule is generic over its node key and written once, and the search
carries interned `u32` states. The layered graph now runs in 6.4 s and the uniform
graph in 5.9 s, both well under the 10 s target, with identical results. The 20 s
ceiling of decision (c) stays as the failing bound.

