# task-018 — Add the scale test (O-08)

**Status:** DONE (with a Review note: see R-6)  
**Complexity:** LOW

## What happened

- **First run.** The first scale run took **37 s**. Profiling (callgrind) showed why:
  - C3 adds every accessed node to the actor set, so almost every state carries a
    distinct authority;
  - on any dense graph of this size the run ends at the 5 000 000-state total budget;
  - about 40 % of the time went to `malloc`/`free` of the `String`-based `Authority`.
- **Changes in `reach.rs`.** The continuity rule is still only `Authority::step`.
  - The arena stores each authority once. `visited` is an FxHash fingerprint chain
    through the arena, confirmed by full equality, so there is no second copy per state.
  - A refused step leaves the authority unchanged, so one copy serves every refused edge
    of a state.
  - The first state per node is collected in a hash map and sorted once at the end.
- **Result.** At the budget ceiling the run takes about **9 s**. All crate tests pass,
  including the property test and the determinism test.

## Tests (`tests/scale.rs`, release only)

Debug builds ignore these tests; CI runs them with `--release` (task-025).

| Test | Graph | Result here |
|---|---|---|
| `a_lab_shaped_graph_is_analysed_in_under_ten_seconds` | layered like the lab graphs: principals → agents → tools / credentials → resources / data; 2 000 nodes, 10 000 edges, 64 seeds | 8.4–9.2 s over 4 runs; asserted < 10 s |
| `a_state_explosion_stops_at_the_total_budget_and_says_so` | uniform random, same size | 9.3–10.2 s, printed; asserts no overshoot, `truncated`, `CONTAINMENT_UNKNOWN` > 0 and every delta entry `partial` |

Both tests also check:
- ≤ 1 000 000 states per search;
- ≤ 5 000 000 states in total;
- ≤ 64 delta entries.

## Review note

The margin to 10 s is thin. `EXECUTION/task-018-parallel-option.patch` holds a variant
that measured **7.3 s / 3.4 s**:
- worker threads run searches ahead of their turn;
- the calling thread keeps a result only if it fits the budget left at its turn,
  otherwise it reruns that search;
- `running_seeds_ahead_matches_running_them_in_turn` proves the output and the budget
  are identical for 1–8 workers at budgets from 0 to 1 000 000.

It uses `std::thread::scope`, which RS-08 forbids in the crate. It was therefore **not
applied**, and it is left for the human decision (R-6).

Ralph Loop: fmt, clippy `-D warnings` (debug and release), crate tests and the release
scale tests are green.
