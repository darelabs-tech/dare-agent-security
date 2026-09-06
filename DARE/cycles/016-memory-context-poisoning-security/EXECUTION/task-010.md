# task-010 — Implement hostile input refusal

**Status:** APPROVED FOR EXECUTION
**Depends on:** task-008, task-009

Reject executable/callback fields, credential-shaped material, control characters, bidi spoofing, path traversal and provider/remote-store fields at every depth. Redaction/refusal must occur before persistence.