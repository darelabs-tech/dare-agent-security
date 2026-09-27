# task-011 — Implement `MultiTurnScenario` model and validation

**Status:** DONE  
**Complexity:** MED

## Files changed

- `crates/dare-multi-turn-security/src/model.rs`: adds `PrincipalSpec`, `ObjectiveSpec`, `ProhibitedSpec`, `CanarySpec` (field `marker`, see task-006), `ConversationSpec`, `MultiTurnScenario`, `GraphSet`, `is_applicable`, `validate` and the shared test fixtures
- `crates/dare-multi-turn-security/src/error.rs`: `StrategyFault` (a run-level error, not a refusal), used by task-013 onward

## Result

`validate` checks:
- the version;
- the bounds (lower-only);
- canaries: at most 16, unique ids and markers, marker shape;
- the composite objective: 2–8 distinct fragments;
- conversations: 1–4, unique ids, and each digest resolves to a supplied graph;
- that every planted canary is declared;
- that the primary invariant is **applicable**.

`is_applicable` implements the "Applicable when" column of Blueprint §4.8 exactly. I03
compares a claim against the claiming conversation's verified authority. I07 needs two or
more conversations **and** two or more distinct `(principal, tenant)` pairs.

## Tests (`model::tests`)

- `a_minimal_scenario_validates`
- `each_structural_rule_fails_with_its_error` (digest mismatch, duplicate canary, bad marker, one fragment, duplicate fragment, > 4 conversations, raised bound)
- `an_undeclared_canary_in_a_graph_is_refused`
- `applicability_follows_the_blueprint_table` (all seven invariants, including "a claim at the verified level is not an escalation" and "the same principal twice is not isolation")
- `an_inapplicable_primary_invariant_is_refused`

## Ralph Loop

- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Test: `cargo test --workspace`: 0 failed (count in the commit message)
- Audit: no dependency change
