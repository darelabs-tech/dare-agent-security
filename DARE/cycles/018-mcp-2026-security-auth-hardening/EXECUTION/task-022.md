# task-022 — AS metadata and issuer boundary evaluators

**Status:** DONE - REVIEW PASS

Evaluate authorization-server metadata consistency and issuer/resource trust boundaries from recorded local evidence. Detect issuer mix-up or unauthorized AS substitution deterministically.

## Evidence

`invariant::issuer_boundary`. Both halves: an authorization server the resource does not advertise, and a selection with no recorded metadata at all — the second because accepting it would mean trusting the selection itself.
