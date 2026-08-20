# task-003 — Verify Action packaging architecture and threat model

**Cycle:** 004 — CI Security Gate  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective
Verify the packaging choice before committing to implementation.

### Primary candidate
Docker container Action containing the repository's compiled Rust CLI.

### Evaluate
- Linux runner support
- build/runtime size and latency
- action metadata requirements
- workspace/evidence mapping
- entrypoint design
- immutable version relationship
- permissions
- untrusted input surface

### Threat model
Include shell injection, path traversal, secret leakage, malicious MCP metadata, scope expansion, and mutable dependency risk.

### Acceptance
Architecture decision is explicit. If Docker is rejected, the replacement must be equally reproducible and must not depend on the consumer having Rust installed.

## DARE execution rule

Do not mark this task complete from code appearance alone. Capture deterministic evidence for the acceptance statements.

If implementation reveals a security-relevant architectural assumption that contradicts `DESIGN.md` or `BLUEPRINT.md`, stop and return to Review rather than silently changing the architecture.
