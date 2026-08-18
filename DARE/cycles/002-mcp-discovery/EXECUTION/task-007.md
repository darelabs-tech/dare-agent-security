# task-007 — Implement discovery redaction and sanitization

## Goal
Ensure credentials and sensitive endpoint material cannot leak through inventory, evidence or diagnostics.

## Required implementation
- Sanitize HTTP userinfo/query/fragment and secret-bearing headers.
- Never serialize Authorization values, bearer/API-key values, refresh tokens or private-key material.
- Represent endpoint identity with safe target id plus optional fingerprint.
- Sanitize SDK/transport/process errors before display.
- Record redaction metadata without recording the secret value.

## Required tests
Inject unique canary secrets through URL, headers, environment/config and synthetic errors. Search serialized inventory, evidence, stdout-equivalent and error strings; every canary must be absent.

## Gates
Standard workspace gates.

## DONE
All canary-secret tests pass and public outputs preserve enough metadata for reproducibility without credential disclosure.