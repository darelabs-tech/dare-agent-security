# task-003 — Move the continuity rule to `dare_attack_graph::v2::continuity`

**Status:** DONE  
**Complexity:** HIGH

## Change

- **`crates/dare-attack-graph/src/v2/continuity.rs` (new).** The C1–C6 rules are
  restructured as an incremental state machine:
  - `Authority { principal, actors }`, with `for_entry`, `acting`, `unset` and
    `component`;
  - `step(&mut self, edge, node_type) -> bool`, which returns false and leaves the state
    unchanged when no rule explains the edge.

  `discontinuity(entry, edges, node_type)` keeps its signature and is now
  `Authority::for_entry` plus `step` in a loop. `MUTATION_PROPERTIES` moves unchanged.
  The rule bodies are the Cycle 023 code, line for line; only their frame changed.
- **`crates/dare-attack-path/src/continuity.rs`** becomes a re-export
  (`discontinuity`, `Authority`, `MUTATION_PROPERTIES`), so `paths.rs` is untouched.
- **`dare_attack_graph::v2`** re-exports the three items.

## Tests

- The six C1–C6 tests move with the code, unchanged.
- Six `step` tests are added, one per rule and one for the initial states:
  - `step_c1_hands_authority_to_the_delegatee`;
  - `step_c2_adds_the_credential_as_principal_and_actor`;
  - `step_c3_adds_the_target_to_the_actors`;
  - `step_c4_switches_the_principal_on_an_explained_mutation`;
  - `step_c5_and_c6`;
  - `initial_states`.

  The step tests also check that a refused step leaves the state unchanged, and that
  with P unset any source acts.

## Equivalence (O-07)

- `every_attack_path_lab_output_keeps_its_baseline_digest`: all 156 Cycle 023 output
  files are byte-identical to the baseline.
- `attack_path_lab` passes (26 scenarios).
- `attack_paths_cli` passes (9 tests), and so does `attack_path_compatibility` (4).
- `dare-attack-path` and `dare-attack-graph` pass: 124 tests, 0 failed.

## Ralph Loop

Green: fmt, clippy `-D warnings --all-targets` on both crates, and the tests above. No
dependency changed.
