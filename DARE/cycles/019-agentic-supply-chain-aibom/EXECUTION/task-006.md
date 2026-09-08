# task-006 — Define closed relationship graph schemas and validation contracts

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-22, AC-23

## Evidence

`src/relationship.rs`. Thirteen relation types, closed.

**AC-22 — an imported relationship word cannot invent a relation type.** `an_imported_relationship_word_cannot_invent_a_relation_type` checks `VENDORS`, `RELATES_TO`, `OTHER` and even lowercase `depends_on` are all refused. A document using its own vocabulary is refused, not stored as a string nobody can reason about.

**AC-23 — a dangling endpoint is refused.** An edge naming a component absent from the graph describes a relationship to something the engine cannot see; evaluating it would mean reasoning about an absence, and a finding about it would name a component nobody can look up.

## Declared and observed are different observations

The distinction the dependency-integrity property rests on. `an_undeclared_dependency_and_a_missing_one_are_different_findings` asserts both directions separately: an edge observed and never declared is an **insertion**, one declared and never observed is a **manifest describing a system that is not running**. Collapsing them into "the edges differ" loses which direction the difference goes, and the two have different fixes.

`a_graph_with_only_one_side_is_not_comparable` is the guard against the obvious false FAIL: a graph of only observed edges describes what was seen, with nothing to compare it to. Reporting every edge as undeclared there would be a finding about the absence of a manifest.

`only_dependency_relations_participate_in_the_declared_observed_comparison` keeps an `ATTESTED_BY` edge from being reported as a dependency insertion.

## Graph bombs

`assert_bounded_depth` refuses a cycle rather than walking it — a dependency cycle is a description no build could have produced, and walking it is how a crafted document turns a bounded engine into a stalled one. Depth is capped at the approved 64.

`identical_edges_deduplicate_deterministically` and `edge_order_does_not_change_the_graph` keep normalization stable: two documents describing the same dependency is the normal case for a merged BOM, and the graph digest must not depend on emit order.
