# task-007 — Redaction and target/auth sanitization

> Status: PENDING REVIEW
> Depends on: task-002, task-004
> Complexity: HIGH

## Objective
Prevent credential and sensitive transport metadata from leaking through inventory, logs, errors or evidence.

## Required implementation
Protect:
- URL userinfo, query strings and fragments;
- Authorization headers;
- bearer/API-key values;
- environment-backed credentials;
- private-key-like material;
- SDK/transport error payloads that may contain request metadata.

Create safe target identity/fingerprint behavior and inventory redaction metadata.

## Tests
Use unique canary secrets in URL/header/env/error fixtures and assert exact canary absence from stdout, stderr, serialized inventory, evidence and typed errors.

## Security invariants
Never depend on perfect secret detection; prevent raw secret fields by design and use redaction heuristics as defense in depth.

## DONE when
Canary-secret suite proves supported output/error paths cannot emit the raw test secrets and all Rust gates pass.
