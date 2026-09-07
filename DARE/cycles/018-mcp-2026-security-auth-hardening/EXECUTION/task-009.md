# task-009 — PKCE and redirect/state evidence schemas

**Status:** DONE - REVIEW PASS

Define structured PKCE, redirect URI and state-correlation evidence. Support deterministic secure/vulnerable fixtures; do not launch a browser or contact an authorization endpoint.

## Evidence

`src/pkce.rs` and `src/redirect.rs`. PKCE records requirement, method and digest binding; no verifier value is stored. Redirect checks three values rather than two — registered, requested, delivered — because a diverted response and a client asking for an unregistered destination are different attacks and a flow can pass one while failing the other.
