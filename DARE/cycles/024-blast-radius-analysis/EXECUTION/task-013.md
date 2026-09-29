# task-013 — Implement `classify.rs`: targets, exposure, routes and frontier

**Status:** DONE  
**Complexity:** HIGH

- **`candidates`** returns every `graph.targets` designation other than the seed, plus
  every RESOURCE or DATA node of another tenant as `CROSS_TENANT_RESOURCE`. A seed with
  no tenant gets none of the second kind (BQ-4). The result is sorted and deduplicated.
- **`classify`** makes one `TargetReach` per candidate that the structural view
  reached:
  - `Exposed` when the uncontained view reached it, with that witness as
    `uncontained_route`;
  - otherwise `Contained` when the uncontained search was not truncated, else
    `ContainmentUnknown`. `CONTAINMENT_UNKNOWN` never carries a frontier.
- **Routes** come from `Found::walk_to`. Their control fields come from Cycle 023
  `path_control`, unchanged.
- **`frontier`** is the held edges on the structural route, sorted.

## Tests (`tests/classify.rs`)

- `exposure_follows_the_uncontained_view`: a FAIL edge gives `Exposed`, with
  `CONTROL_FAILED` and its failed guard. A PASS edge gives `Contained`, with that edge
  as frontier.
- `a_truncated_uncontained_search_never_claims_containment`: with `max_states = 1`,
  both targets are `ContainmentUnknown`.
- `the_seed_is_never_its_own_target_and_unreached_targets_are_absent`: an unguarded
  route is `CONTROL_UNDECIDED`.
- `cross_tenant_candidates_need_a_seed_tenant` (BQ-4).
- `every_contained_target_has_a_non_empty_frontier`: 200 random graphs; every frontier
  edge is held.
- `no_random_graph_yields_a_false_containment` (O-03):
  - **Corpus:** 200 fixed-seed xorshift graphs. Each has 26–34 nodes of 9 types,
    about 1.5 edges per node of all 14 edge types, a random guard state, and a named
    principal on a third of the edges. Up to 4 seeds per graph; `max_depth` is 5.
  - **Oracle:** an independent exhaustive enumeration of **walks**, with no state
    deduplication, applying the continuity step. The oracle reach equals the search's
    `reached` in both views.
  - **Result:** 3014 `(seed, target)` pairs, 1657 `Contained` and 1357 `Exposed`.
    **0 false `CONTAINED`.**

Ralph Loop: clippy `-D warnings` and fmt clean; crate tests green.
