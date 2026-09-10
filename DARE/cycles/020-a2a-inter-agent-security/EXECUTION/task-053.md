# task-053 — Run Cycle 012-019, MCP and coverage compatibility regressions

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Prove this cycle is additive: nothing an earlier cycle established moved.

## Files changed

None. This task is verification, and a task that had to change something to pass would have found a regression rather than proved its absence.

## What was run, and why each matters

**MCP, coverage and product** — 600 tests.

`dare-coverage` is where this cycle made its riskiest edits: ten properties appended to the v2 registry, eleven predicates added, the predicate enum in `property.schema.json` extended 46 -> 57, and a new profile. Each of those is one careless line away from changing a denominator. `dare-mcp-discovery` and `dare-product` are downstream of the registry and would break if a property id or schema shape moved.

**Cycles 013 through 019 engines** — 2199 tests.

Cycle 013 (prompt injection), 014 (tool security), 015 (identity), 016 (memory), 017 (RAG), 018 (MCP auth) and 019 (supply chain). Each owns semantics this cycle *projects* rather than restates, and each would fail here if this cycle had absorbed verdict authority it does not hold.

**Whole workspace** — 3733 tests, zero failures.

## The compatibility claims, and where each is pinned

| Claim | Pinned by |
|---|---|
| the v1 MCP registry gained nothing | `the_v1_registry_gained_nothing_from_this_cycle` |
| no earlier profile's denominator moved | `no_earlier_profile_denominator_moved`, on literal counts |
| this cycle's ten new properties reached no earlier profile | `this_cycles_ten_new_properties_reached_no_earlier_profile` |
| the two inherited property ids are unchanged | `the_two_inherited_properties_keep_their_public_identifiers` |
| the registry edit was purely additive | `a2a_properties.rs`, by before/after id comparison |
| existing serialized facts still decode | every new `Facts` field carries `#[serde(default)]` |
| the Cycle 019 profile is untouched | `the_cycle_019_profile_is_untouched_and_still_selects_ten_properties` |

The profile and registry claims are the ones that would fail *quietly*. A coverage percentage is a fraction whose denominator is a profile's property count; if this cycle had changed an earlier profile, every assessment already filed against it would silently mean something different and nothing about the number would look wrong.

## Commands executed

```
cargo test -p dare-mcp-discovery -p dare-coverage -p dare-product
cargo test -p dare-prompt-injection -p dare-tool-security -p dare-identity-security \
           -p dare-memory-security -p dare-rag-security -p dare-mcp-auth-security \
           -p dare-supply-chain-security
cargo test --workspace
```

## Result

600 + 2199 regression tests passing; the whole workspace green at **3733 tests, zero failures**.

## Evidence

```
MCP + coverage + product: 600
cycles 013-019 engines: 2199
workspace total: 3733
failures: 0
```

## Review result

**REVIEW PASS**
