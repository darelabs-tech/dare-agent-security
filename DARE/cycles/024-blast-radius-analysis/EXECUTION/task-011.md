# task-011 — Implement the reach index and the structural search

**Status:** DONE  
**Complexity:** HIGH

## Change (`crates/dare-blast-radius/src/reach.rs`)

- **`Indexed`:** node, edge and out-edge maps built once. Out-edges are sorted by
  `(target, edge id)` (AD-07).
- **`initial_authority(kind, seed)`** follows §6.2.
- **`search(index, seed, init, view, bounds, budget, excluded)`** is a FIFO BFS over
  authority states in an arena, with `visited: HashSet<(node, Authority)>`. Each step
  goes through `Authority::step`, the shared C1–C6 rule from task-003.
- **What it records:** `refused_steps`, `depth_cut` (a state at `max_depth` that has
  out-edges), and `MaxStates`/`MaxStatesTotal`, checked before each push. The first
  reach of each node is its witness.
- **`Found::walk_to(node)`** returns the witness walk with the authority on arrival at
  each node.

Two refinements, recorded in REGRESSION:
- **R-2.** The search is over walks, not simple routes. The Blueprint's parent-chain
  check, combined with `(node, authority)` deduplication, could lose an uncontained route
  and report false containment.
- **R-3.** A compromised component cannot use a principal it never acquired (C3 is
  unchanged).

## Tests (`crates/dare-blast-radius/tests/reach.rs`)

- `initial_states_follow_the_kind_table`.
- `continuity_decides_every_step`, with C1, C2, C3, C5 and C6 in one graph:
  - the reached set;
  - the refused access under an unacquired principal, counted;
  - the witness walk;
  - the authority carried along it.
- `a_component_continues_through_unnamed_access_credentials_and_delegation` (R-3).
- `walks_revisit_a_node_only_under_new_authority_and_cycles_terminate` (R-2): a cycle,
  a self-loop, and a vault reached only on a second visit to a tool under the credential.
- `depth_cut_and_state_bounds_are_reported`: `depth_cut`, `MaxStates` (2 states), and
  `MaxStatesTotal` with a budget of 1.
- `the_witness_is_the_first_shortest_walk_in_id_order`: the same witness with the edge
  array in either order.

Ralph Loop green: fmt, clippy `-D warnings --all-targets`, 8 tests.
