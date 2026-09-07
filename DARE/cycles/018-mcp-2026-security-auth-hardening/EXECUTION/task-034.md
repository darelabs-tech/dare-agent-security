# task-034 — Replay adapter with semantic scenario binding

**Status:** DONE - REVIEW PASS

Implement local replay with semantic scenario binding across authorization-relevant evidence. A trace cannot manufacture its own resource, issuer, audience, scope, registration or credential authority. Unknown semantic references refuse before invariant evaluation.

## Evidence

`src/replay.rs`. The Cycle 017 lesson applied: `assert_matches` compares protocol and operation semantics for every observed request, not just `scenario_id`. A trace cannot relabel a legacy request as current, rewrite the body operation, or introduce a request the scenario never declared. Routing metadata stays free because it is what the binding invariants judge, and binding it would make them untestable through replay.
