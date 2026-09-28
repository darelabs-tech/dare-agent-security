# task-005 — Implement the v2 control-state rule and `validate_graph_v2` invariants 1–7

**Status:** DONE  
**Complexity:** HIGH

## Change

- `src/v2/control.rs` holds `edge_control`, `path_control` and `is_structural`, following
  BLUEPRINT §7.4:
  - BQ-1 exempts `BELONGS_TO_TENANT` and `ENFORCED_BY`;
  - every other unguarded edge is `UNASSESSED`;
  - guards aggregate with FAIL > ERROR > INCONCLUSIVE > PASS.

  `path_control` returns the state together with the sorted `failed_guards` and
  `undecided_edges`.
- `src/v2/validate.rs` provides:
  - `validate_graph_v2`, which checks invariants 1–5 and 7 and the sealed graph id;
  - `validate_paths_v2`, which checks invariant 3 for paths and invariant 6. It
    recomputes the path id (v1 formula), the evidence status, the control state together
    with its `failed_guards` and `undecided_edges`, and the impact factors. It also checks
    that paths are simple and connected, that each is in the list of its feasibility, and
    that the truncation flag agrees with `stopped_by`;
  - `validate_projection_report`;
  - shared helpers `graph_id_v2`, `path_id`, `path_status` and `impact_factors`, which
    `dare-attack-path` will call so each rule has one implementation.
- **Deviation from the Blueprint wording, recorded here.** §4.7 lists all seven invariants
  under `validate_graph_v2`. Paths live in a separate document (`attack-paths.json`), so
  the path invariants run in `validate_paths_v2(graph, doc)`, which the CLI calls on every
  write. The rules themselves are unchanged. The TASKS note already places the control
  rule in this crate.

## Tests

- `control.rs` unit test `the_state_is_never_better_than_the_weakest_edge` enumerates all
  780 combinations (1–4 edges × {no guard, PASS, FAIL, INCONCLUSIVE, ERROR}).
- The structural exemption and mixed guards each have a unit test.
- `v2_contract.rs` has one test per invariant: `invariant_1` … `invariant_7`. Invariant 6
  covers a doctored `control_state`, a doctored status and doctored impact factors, and
  each is refused.
- `a_path_must_be_in_the_list_of_its_feasibility` and
  `the_projection_report_is_bound_to_its_graph` cover the remaining checks.

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-graph` (8 unit tests and 13
contract tests, with `v1_unchanged` still passing).
