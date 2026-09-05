# task-006 — Define tool-security corpus-entry and replay trace schemas

**Status:** APPROVED FOR EXECUTION

## Objective
Create versioned corpus-entry and replay-trace contracts for local Tool Security validation.

## Required work
- Corpus entries must declare class/family, property, tool-surface, objective/policy, source/trust, invariant, safety/provenance and synthetic reference observations without embedding an expected verdict.
- Replay traces must contain sanitized typed observations only.
- Reject arbitrary executable fields, remote targets, credentials and path traversal.

## Acceptance
- Secure/vulnerable/benign fixtures validate; hostile fixtures refuse.
- Replay schema is sufficient to reproduce verdict logic offline.
- No expected-verdict smuggling is possible.
