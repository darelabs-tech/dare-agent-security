# task-028 — Client-registration trust evaluator

**Status:** DONE - REVIEW PASS

Evaluate whether registration metadata came from an approved trust path and whether self-declared/legacy registration evidence is being over-trusted. Do not require live CIMD/DCR.

## Evidence

`invariant::registration_trust`. Untrusted provenance relied upon is the violation; recording it without relying on it is not.
