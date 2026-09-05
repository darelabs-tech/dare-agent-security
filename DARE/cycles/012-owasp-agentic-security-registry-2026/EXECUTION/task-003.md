# task-003 - Design multi-namespace property ID schema

**Cycle:** 012 - OWASP Agentic Security Registry 2026  
**Status:** READY FOR EXECUTION

## Objective
Evolve the property ID contract to accept `MCP.*` and `AGENT.*` without breaking existing serialized data.

## Required work
- Version the schema change.
- Preserve existing MCP IDs unchanged.
- Reject unsupported future namespaces.
- Add positive and negative ID tests.

## Boundaries
No silent migration or semantic reinterpretation of legacy IDs.

## Acceptance
`MCP.*` remains valid, `AGENT.*` becomes valid, unknown namespaces fail closed, and compatibility behavior is documented.
