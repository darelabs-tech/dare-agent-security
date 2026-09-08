# task-030 — Implement dependency-integrity evaluator

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-38, AC-39, AC-40, AC-49

## Evidence

`src/invariant.rs` — `dependency_integrity`.

**AC-39/AC-40 — insertion and omission are separate findings.** `an_inserted_dependency_and_a_missing_one_are_separate_findings` stages a manifest expecting `app -> react` against a graph observing `app -> left-pad`, and asserts **two** violations: one naming `left-pad` (observed, never declared) and one naming `react` (declared, never observed).

One symmetric "the graph differs" finding would leave the operator to reconstruct which edge was inserted and which was missing, and those have different causes and different remediations.

**AC-38 — deterministic PASS as well as FAIL.** The evaluator skips entirely when `comparable` is false. With only one side there is nothing to compare and every edge would read as a difference — a run with a BOM and no manifest would report its whole dependency graph as inserted. `RelationshipGraph::is_comparable` gates it, and the coverage contract turns the skip into INCONCLUSIVE rather than PASS.

**Edges that both sides record collapse to one.** `collapse_declared_and_observed` runs in `EvidenceBuilder::with_manifest`, so an agreeing dependency is a single `DeclaredAndObserved` edge rather than one "declared but not observed" plus one "observed but not declared" for the same edge.

**The violation names edges, not counts.** `undeclared_edge_keys` and `unobserved_edge_keys` carry canonical edge keys into the reason text.
