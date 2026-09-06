# task-010 — Scope challenge and step-up schema

**Status:** DONE - REVIEW PASS

Define 401/403/insufficient-scope challenge and step-up evidence, including requested scopes, prior scopes, challenged scopes, bounded retry count and resulting effective scope set.

## Evidence

`src/scope.rs`. Union semantics: the retry must cover initial required plus challenged. `dropped_scopes()` names what went missing rather than returning a boolean, because "a scope was dropped" is not actionable. Retries hard-bounded at two; the ceiling itself is allowed and one more is refused.
