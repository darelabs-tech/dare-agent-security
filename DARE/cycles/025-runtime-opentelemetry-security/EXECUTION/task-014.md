# task-014 — Implement evaluators B-3 (principal) and B-4 (tenant)

**Status:** DONE  
**Complexity:** MED

- **B-3 (`principal.rs`).** Agent and tool spans are checked.
  - The principal is read from the policy's `principal_keys`; the first present key
    wins.
  - The expected principal is the acting agent's declared principal, or else the
    outermost agent span's (R-4). A mismatch → `principal_mismatch`, carrying the key and
    a fingerprint.
  - A missing principal or no `principal_keys` → gap.
- **B-4 (`tenant.rs`).**
  - Retrieval spans are judged under B-4R (`AGENT.RAG.TENANT_DOCUMENT_ISOLATION`), memory
    operations under B-4M (`AGENT.MEMORY.TENANT_BOUNDARY`).
  - The tenant comes from `tenant_keys` and must equal the acting agent's policy tenant.
    A mismatch → `tenant_mismatch`.
  - A missing tenant or no tenant keys → gap.

## Tests

- **B-3:** a constant declared principal passes; a tool under another principal fails;
  without a declaration the outermost agent sets the principal (fail and pass cases); a
  missing principal or no keys is INCONCLUSIVE.
- **B-4:** the same tenant passes and another tenant fails; memory spans judge only B-4M;
  a missing tenant is INCONCLUSIVE.

Ralph Loop green.
