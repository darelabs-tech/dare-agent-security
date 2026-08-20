# Cycle 008 — Final Proof

## Acceptance matrix

1. Reconciliation: `IMPLEMENTATION-NOTES.md` and `cycle008_reconcile.rs`.
2. Versioned schema: `schemas/attack-graph/v1/attack-graph.schema.json`.
3. Node taxonomy: `src/node.rs`; fixture matrix.
4. Edge taxonomy: `src/edge.rs`; fixture matrix.
5. Stable node IDs: `build_node_id`; adversarial duplicate test.
6. Stable edge IDs: `build_edge_id`; scope-order unit test.
7. Authority context: `src/authority.rs`; confused-deputy fixture.
8. Four evidence states: `src/evidence.rs`; fixtures.
9. Evidence state is separate from verdict: `model::EdgeEvidence` and `EdgeSecurity`.
10. Proven evidence references: evidence invariant unit test.
11. Inference provenance: evidence invariant validation and inferred fixture.
12. Coverage dimensions preserved: `model::EdgeSecurity`.
13. Real property mappings: `src/mapping.rs` registry-ID test.
14. Deterministic paths: `src/path.rs`; fixture matrix.
15. Weakest-edge state: `weakest_edge_and_impact_semantics_are_visible`.
16. Provenance/source digests: `GraphSources` and schema.
17. Canonical JSON: `src/canonical.rs`, `src/provenance.rs`.
18. Derived Mermaid/DOT views: `src/render.rs`.
19. Hostile input and bounds: `tests/adversarial.rs`.
20. Known synthetic topology: five files under `fixtures/attack-graph`.
21. Authorization mutation: `auth-mutation.json`.
22. Confused deputy: `confused-deputy.json`.
23. Credential reachability: `inferred-credential.json`.
24. Blocked/NOT_TESTED: `blocked-destructive.json`.
25. CI determinism/path regression: `attack-graph-mvp` job and crate tests.
26. Final proof: this document.
27. Approval state: human approval is recorded in `APPROVAL.md`; the pre-approval absence criterion was superseded by that explicit approval.

## Validation

Mandatory Ralph Loop commands and their final results are recorded in the execution handoff. Graph generation is offline and analysis-only; no exploit path or state-changing operation was executed.
