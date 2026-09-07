# task-031 — Reuse Cycle 015 identity semantics

**Status:** DONE - REVIEW PASS

Add compatibility/composition tests proving Cycle 018 principal, tenant and delegation handling reuses Cycle 015 semantics and does not permit metadata/token claims to relabel authority.

## Evidence

`src/compat.rs` and `src/identity.rs`. `PrincipalKind` is re-exported from Cycle 015 and asserted to round-trip; this cycle adds no principal kind of its own, and a test proves an MCP-specific kind is refused.
