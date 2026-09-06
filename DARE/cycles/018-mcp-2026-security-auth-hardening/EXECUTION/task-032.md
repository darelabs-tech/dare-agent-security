# task-032 — Reuse Cycle 003 final-operation binding

**Status:** DONE - REVIEW PASS

Compose successful authentication/resource evidence with Cycle 003 final-operation authorization binding. A permit/token-related success must not survive authorization-relevant method/name/argument/context mutation without re-evaluation or refusal.

## Evidence

`src/compat.rs` `authorization_relevant_change()`. Reports which fields moved rather than a boolean, so a finding can say what changed. Casing alone is not a change. Re-evaluation or refusal after a change is correct behaviour and produces no finding.
