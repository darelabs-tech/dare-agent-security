# task-015 — Canonical digests and semantic bindings

**Status:** DONE - REVIEW PASS

Implement deterministic canonical digests for scenario, request, auth metadata, resource/audience, PKCE/state, scope, registration and credential-separation evidence. Bind replay observations to approved scenario authority, not merely IDs.

## Evidence

`src/canonical.rs` and `harness::assert_requests_bound`. Canonical-JSON digests with sorted keys, so serialization order cannot change an identity. `assert_safe_identifier` refuses control characters, bidi overrides, invisibles, padding and path shapes, and never echoes what it refused.
