# task-006 — Define source trust-boundary and injection-family enums

**Status:** READY FOR EXECUTION

## Objective
Implement the approved closed InjectionFamily, SourceKind and TrustLevel types.

## Acceptance
- direct and indirect source boundaries are machine-readable and distinct;
- unknown enum values fail closed;
- tool poisoning/RAG/A2A classes are not silently folded into Cycle 013;
- deterministic serialization tests pass.
