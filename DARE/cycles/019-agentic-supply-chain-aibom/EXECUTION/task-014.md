# task-014 — Implement normalized relationship graph and deterministic edge semantics

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-22, AC-23, AC-38, AC-39, AC-40

## Evidence

`src/relationship.rs`.

**AC-22 — the relation enum is closed.** 13 typed relations, no `OTHER`, unknown wire values fail to decode. `is_lineage()` and `is_dependency()` partition them by question rather than by name, so `a_dependency_edge_is_not_lineage` (in `model_lineage.rs`) holds structurally: a model depending on numpy is not derived from numpy, and reading dependency edges as lineage would make every model lineage the entire graph.

**AC-23 — dangling endpoints fail closed.** `assert_no_dangling` refuses an edge whose source or target names no component. A dangling edge is a dependency on something nobody inventoried, which is precisely the thing an inventory is for.

**AC-39/AC-40 — insertion and omission are separate answers.** `undeclared_dependencies` returns observed edges the manifest never declared (an inserted dependency); `unobserved_dependencies` returns declared edges nothing observed (a missing one). Two methods rather than one symmetric difference, because the two findings have different causes and different remediations, and an operator handed a single "the graph differs" list has to reconstruct which is which.

**AC-38 — deterministic PASS as well as FAIL.** `is_comparable` gates both: with no manifest edges there is nothing to compare and the answer is INCONCLUSIVE, never PASS. A graph that agrees with an empty expectation agrees with nothing.

**Depth and cycles.** `assert_bounded_depth` enforces `HARD_MAX_DEPENDENCY_DEPTH = 64` and refuses cyclic graphs rather than looping. A cycle in a dependency graph is malformed input, and an engine that recursed into one would be a denial-of-service surface reachable from a file.

**Edges are order-independent.** `edge_key()` gives each edge a canonical key, so two documents listing the same relationships in different orders produce the same graph and the same digest.
