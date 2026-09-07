# task-008 — Synthetic token claims/resource/audience schema

**Status:** DONE - REVIEW PASS

Define synthetic token-evidence claims for validity state, resource and audience binding without accepting raw bearer tokens or performing signature/JWKS/introspection work. Raw credentials remain prohibited.

## Evidence

`src/token.rs`. A bounded projection: synthetic id, issuer, subject, audience, resources, scopes and a fixture-declared validity state. No raw token field exists. Validity and binding stay independent questions — a rejected token that names the right resource is still bound to it — so one finding never hides the other.
