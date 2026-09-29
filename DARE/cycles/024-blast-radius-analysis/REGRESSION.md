# Cycle 024 — Regression and refinement record

**Status:** IN PROGRESS. This record is completed by task-028.

## Blueprint refinements made during execution

Each entry fixes a rule the Blueprint stated in a form the actual behaviour of the code
could not satisfy. None crosses a frozen boundary in `APPROVAL.md`.

| # | Blueprint text | What the code does, and why | Task |
|---|---|---|---|
| R-1 | §7.3 / task-001: the goldens are the SHA-256 of the six outputs of each ATTACK-PATH-LAB scenario, run fresh through the engines | The engines stamp evidence with the wall clock, and the prompt-injection, multi-turn and static supply-chain results differ between runs. A fresh run's outputs are therefore stable within one run (the lab's double run) but not across runs. The goldens run `validate attack-paths` over a frozen snapshot of the 35 unique engine runs, taken at the baseline before any code change (`tests/fixtures/attack-path-lab-frozen/`, 2.3 MB). They pin the same 156 files. The fresh lab still runs in CI, so the snapshot cannot drift from what the engines emit without the lab noticing | 001, 002 |
| R-2 | §6.3: a step is attempted only when `e.target` is not on the parent chain (simple routes), with `visited` keyed by `(node, authority)` | Together, these two rules can lose an uncontained route. A state first reached through a chain containing X blocks every later chain to the same state, and that chain then refuses to pass X again. A target could be reported `CONTAINED` while an uncontained route exists, which breaks O-03 and the frozen containment boundary. The search is therefore over **walks**: no parent-chain check, `visited` keyed by `(node, authority)`. Every state reachable within `max_depth` is found at its least depth. A walk re-enters a node only under a different authority, so it terminates. Witness routes are shortest walks, and a node repeats in one only when the authority differs (`walks_revisit_a_node_only_under_new_authority_and_cycles_terminate`) | 011 |
| R-3 | DESIGN §4.2: `COMPONENT_COMPROMISE` means the component "acts under whatever authority its edges carry" | The component starts with P unset and A = {seed}. The continuity rule is unchanged (frozen), so C3 refuses an access that names a principal the walk never acquired, even from a compromised component; the step is counted in `refused_steps`. The component goes on through unnamed accesses, credentials (C2) and delegations (C1) (`a_component_continues_through_unnamed_access_credentials_and_delegation`). The wording in the concept page follows this | 011 |

