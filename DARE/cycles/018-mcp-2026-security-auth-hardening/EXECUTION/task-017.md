# task-017 — Normalized MCP auth observation model

**Status:** DONE - REVIEW PASS

Create a closed normalized observation model for protocol, headers, PRM, AS metadata, issuer, token/resource/audience, PKCE, redirect/state, scope challenges, registration trust, credential flow and identity metadata. Adapters cannot assert final verdicts.

## Evidence

`src/observation.rs`. Sixteen closed variants and no seventeenth for a verdict — an adapter can only say what it saw. `EvidenceText` masks at construction rather than at render, and keeps a digest of the original so two sightings correlate without the original being retained.
