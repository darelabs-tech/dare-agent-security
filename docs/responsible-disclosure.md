# Responsible disclosure (Cycle 007)

## Publication states

| State | Meaning |
|-------|---------|
| `PUBLIC` | Safe to publish summary |
| `DISCLOSURE_PENDING` | Coordinated disclosure in progress |
| `EMBARGOED` | Temporary hold |
| `REDACTED` | Details withheld |
| `FIXED` | Upstream remediated |

## Must not auto-publish

- live secrets or credentials;
- unpatched critical exploit chains;
- production endpoints;
- unnecessary exploit detail.

## Export

Use publication-safe export (`dare_benchmark::publication_safe_export`). Embargoed/redacted exports redact repository identity and suppress FAIL detail until `FIXED`/`PUBLIC`.

## Human validation

Positive FAIL review, negative PASS/no-finding review, and ambiguous gap review are recorded in an append-only ledger that does not mutate machine evidence.
