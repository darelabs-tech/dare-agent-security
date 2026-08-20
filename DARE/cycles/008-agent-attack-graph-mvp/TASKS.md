# Cycle 008 — Tasks

**Status:** EXECUTED (18/18 DONE)  
**Approval:** APPROVED (2026-08-20)

## task-001 — Reconcile post-Cycle-007 `main`
**Status:** DONE
Inspect actual inventory, authorization, coverage, benchmark, evidence, canonicalization, CLI and schema conventions.

## task-002 — Define Attack Graph schema
**Status:** DONE
Create the versioned canonical graph schema.

## task-003 — Define node taxonomy and stable node IDs
**Status:** DONE
Implement reviewed node types and deterministic IDs.

## task-004 — Define edge taxonomy and stable edge IDs
**Status:** DONE
Implement semantic edge types and deterministic IDs.

## task-005 — Implement authority context
**Status:** DONE
Represent principals, delegated authority, tenant, credential and authorization context.

## task-006 — Implement edge evidence model
**Status:** DONE
Support `OBSERVED`, `STATICALLY_PROVEN`, `INFERRED`, `NOT_TESTED` with strict invariants.

## task-007 — Implement Graph Fact Extractor
**Status:** DONE
Normalize Cycle 001/002/003/006/007 artifacts into graph facts.

## task-008 — Implement deterministic Graph Builder
**Status:** DONE
Build canonical graph from normalized facts.

## task-009 — Implement property-to-graph mappings
**Status:** DONE
Map relevant security properties to graph semantics without changing verdicts.

## task-010 — Implement bounded Attack Path engine
**Status:** DONE
Derive deterministic paths with cycle/depth/path-count controls.

## task-011 — Implement path status and impact factors
**Status:** DONE
Apply weakest-edge semantics and deterministic path annotations.

## task-012 — Implement graph provenance and digest
**Status:** DONE
Bind graph to target, engine, profile, plan, evidence and optional benchmark inputs.

## task-013 — Implement Mermaid/DOT views
**Status:** DONE
Generate safe derived visualizations from canonical JSON.

## task-014 — Build graph-specific synthetic fixtures
**Status:** DONE
Add safe read, confused deputy, inferred credential, blocked/destructive and auth/execution mutation scenarios.

## task-015 — Add adversarial graph-input tests
**Status:** DONE
Test hostile labels, duplicate IDs, malformed references, path explosion, huge graphs and secret leakage.

## task-016 — Extend CLI / output integration
**Status:** DONE
Expose graph generation/path queries through the existing CLI architecture.

## task-017 — Add CI regression coverage
**Status:** DONE
Test graph determinism, schema invariants, path semantics, redaction and bounds.

## task-018 — Documentation and final DARE proof
**Status:** DONE
Document taxonomy, evidence semantics, path semantics, limitations and acceptance evidence.
