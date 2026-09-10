# task-003 — Additive registry design for Cycle 020 A2A properties with compatibility tests

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Add the ten approved A2A properties to the v2 agentic registry, and prove the change is additive rather than asserting it.

## Files changed

- `schemas/coverage/v2/registry.json` (ten properties appended)
- `schemas/coverage/v2/property.schema.json` (predicate enum extended)
- `crates/dare-coverage/tests/a2a_properties.rs` (new)

## Commands executed

```
python -c "<compare registry before/after by property id>"
cargo test -p dare-coverage --test a2a_properties
cargo test -p dare-coverage
```

## Result

**Registry 48 → 58 properties.** A before/after comparison by id reports:

```
pre-existing changed: []
removed: []
added: ['AGENT.A2A.PEER_IDENTITY_BINDING', 'AGENT.A2A.DISCOVERY_TRUST_BOUNDARY',
        'AGENT.A2A.SKILL_AUTHORIZATION', 'AGENT.A2A.MESSAGE_CONTEXT_BINDING',
        'AGENT.A2A.TENANT_BOUNDARY', 'AGENT.A2A.DATA_SCOPE_BOUNDARY',
        'AGENT.A2A.REPLAY_BOUNDARY', 'AGENT.A2A.PROTOCOL_NEGOTIATION_INTEGRITY',
        'AGENT.A2A.EXTENSION_TRUST_BOUNDARY', 'AGENT.A2A.PUSH_NOTIFICATION_BOUNDARY']
```

Not one pre-existing entry differs byte-for-byte.

**The two inherited properties are frozen, and a test says so verbatim.** `the_two_inherited_properties_are_unchanged` asserts both predicate lists exactly. They are the obvious thing to "improve" while implementing the cycle that uses them, and improving one would silently change every assessment already filed against it.

**No parallel namespace.** `no_parallel_a2a_namespace_was_introduced` sweeps both registries for a top-level `A2A.*`. Two places to look for one risk is worse than one imperfect place, because nothing ever fails to tell a reader which is authoritative.

**The family count did not move.** `the_agentic_risk_family_count_is_still_exactly_ten` — Cycle 020 adds properties to an existing family and creates none.

**The agentic baseline profile was not extended.** `the_agentic_baseline_profile_keeps_its_a2a_selection_and_level`. That profile already carries `AGENT.A2A.MESSAGE_AUTHENTICITY`, so adding the ten new properties there would have been the natural way to make them visible — and would have changed a denominator eight cycles of assessments were filed against.

**The registry cites the taxonomy, not the protocol.** `the_registry_records_the_risk_taxonomy_rather_than_the_protocol` asserts every A2A entry cites `OWASP_AGENTIC_TOP10_2026` and nothing else. A2A 1.0.0 supplies evidence *shapes*, and recording it in the registry as well would create two sources of truth that must agree — the mistake Cycle 019 corrected by keeping interchange formats in the provenance record only.

## A correction the tests forced

The first registry edit failed six `dare-coverage` tests with:

```
schema validation failed at /applicability/predicates/2:
"peer_authentication_evidence_present" is not one of "tools_present", ... or 44 other candidates
```

The predicate vocabulary is enumerated in `schemas/coverage/v2/property.schema.json`, and adding a property that gates on a predicate the schema does not know is a registry that cannot load. The enum was extended from 46 to 57 entries.

This is the schema doing its job: a predicate that existed only in Rust would have been unenforceable from the registry side, and a registry that referenced it would have failed at load time in whichever consumer noticed first.

## Evidence

```
cargo test -p dare-coverage --test a2a_properties
test result: ok. 14 passed; 0 failed

cargo test -p dare-coverage
test result: ok. 168 passed (lib) + 14 + 7 + 3 + 6 + 1 + 9 + 14 + 16 + 12 + 12 + 11 across suites; 0 failed
```

## Review result

**REVIEW PASS** — additive, and proved additive.
