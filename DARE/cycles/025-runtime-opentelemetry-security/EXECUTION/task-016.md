# task-016 — Implement T-1 (confidentiality, BQ-3) and T-2 (completeness)

**Status:** DONE  
**Complexity:** MED

## T-1 (`confidentiality.rs`)

- **What is scanned:** every span name, span attribute, resource attribute and event
  attribute, nested texts included.
- **Violations:**
  - a credential marker or a bearer token (a local copy of the product rules, BQ-3);
  - an e-mail address (conservative `local@label.tld` with an alphabetic TLD);
  - a credential-bearing header attribute (`sensitive_header`);
  - a GenAI content key when the policy does not allow capture, or when there is no
    policy (`content_captured`).
- **Deduplication:** one violation per (reason, key, value fingerprint), at its first
  span, so a resource leak is reported once.
- **Gaps:** a value above 64 KiB is `OversizeValue`. Structural gaps do not apply (R-5).

## T-2 (`completeness.rs`)

- **With a policy:** for each `required_operations` kind, a span missing the mapping's
  required keys → `required_key_missing`. Structural and drop gaps on those kinds →
  INCONCLUSIVE.
- **Without a policy:** structure only.
- **A required kind absent from every trace:** decided at run level in task-017.

## Tests

- **T-1:**
  - `the_local_markers_equal_the_products`: via the `dare-attack-graph` dev-dependency.
  - A clean trace passes.
  - Six leak classes fail, and none echoes its value.
  - A leak in a span name is keyed `span.name`.
  - Content is allowed when the policy says so.
  - A repeated resource leak is reported once.
  - An oversize value is INCONCLUSIVE.
  - `the_email_shape_is_conservative`.
- **T-2:** keys present pass; a missing key fails; a drop gap is INCONCLUSIVE; with no
  policy a sound trace passes and an orphan does not.

Ralph Loop: clippy `-D warnings` and fmt clean; 73 crate tests pass.
