# task-029 — Credential separation evaluator

**Status:** DONE - REVIEW PASS

Evaluate that inbound MCP credentials are not reused, forwarded or confused with upstream/downstream API credentials. Compare only synthetic identities/digests, never raw secrets.

## Evidence

`invariant::credential_separation`. Forwarding detected structurally by digest, never by comparing secrets that were never stored.
