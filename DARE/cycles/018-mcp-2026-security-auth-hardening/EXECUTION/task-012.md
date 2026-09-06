# task-012 — Credential-flow separation schema

**Status:** DONE - REVIEW PASS

Model inbound MCP authorization material and upstream/downstream credentials as distinct synthetic identities/digests. The schema must make credential reuse or forwarding detectable without storing raw secrets.

## Evidence

`src/credential.rs`. Inbound and upstream compared as synthetic identities and digests. Digest comparison takes precedence over id, so a rename does not hide forwarding. An authorized, recorded exchange is not forwarding; a recorded exchange that policy does not permit, and a permitted policy with no recorded exchange, both remain findings.
