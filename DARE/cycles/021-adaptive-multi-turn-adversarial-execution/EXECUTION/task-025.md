# task-025 — Build MULTITURN-LAB entries 001–018 (refusal, fragmentation, grooming)

**Status:** DONE  
**Complexity:** MED

## Files changed

- `crates/dare-multi-turn-security/src/corpus.rs` (new): entry type, builders, and the `CORPUS` table shared with task-026

## Result

The entries record a class, a theme, a primary invariant, and staging (graphs, scenario, and an agent or a transcript). No expected verdict is stored.

| Range | Theme | Content |
|---|---|---|
| 001–006 | Refusal | 2 controls (3 and 6 reframes), 2 erosion attacks, 2 gaps (no-transition; first-contact compliance → `NO_BASELINE_REFUSAL` + delegated finding) |
| 007–012 | Fragmentation | 2 controls (3 and 2 fragments), 3 attacks (in order, reversed, 2-fragment), 1 non-exhaustive gap |
| 013–018 | Grooming | 2 controls, 3 attacks (immediate, after 2 claims, a Write-level claim), 1 evidence-budget gap |

## Corrections found by this corpus

1. **Graph rule 10 (task-009).** Parallel edges to one successor (e.g. `REFUSED→x` and `DEFLECTED→x`) were counted as separate paths, so an ordinary 6-reframe refusal graph reported 382 paths. A path is now a sequence of distinct nodes, and successors are de-duplicated. Test: `graph::tests::rule_10_parallel_edges_to_one_successor_are_one_path`.
2. **A turn-bound GAP cannot be staged.** A lowered `max_turns_per_conversation` is checked against graph depth before the first turn (rule 9), so the graph is refused, not stopped mid-run. This is the intended static behaviour. Mid-run budget gaps therefore lower the evidence byte budget instead (`with_byte_budget`), and non-exhaustive gaps remove an edge (`without_edge`).

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 3939 passed, 0 failed
- Audit: no dependency change
