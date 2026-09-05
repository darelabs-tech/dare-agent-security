# task-017 — Add hostile parser/schema fixtures and executable-field refusal

**Status:** READY FOR EXECUTION

## Objective
Threat-test scenario/corpus loading as untrusted input.

## Acceptance
- reject script/shell/eval/callback/unknown fields;
- reject path traversal, duplicate IDs, enum spoofing, schema downgrade, digest substitution and excessive sizes;
- test hostile Unicode/canonicalization;
- no fixture executes arbitrary code.
