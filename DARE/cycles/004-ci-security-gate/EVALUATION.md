# Cycle 004 Capability Evaluation

## Decision

**Recommended Cycle 004:** CI Security Gate / GitHub Action.

## Why now

After the first three cycles, the project has the three prerequisites needed for continuous validation:

```text
Evidence contract
      +
Passive discovery
      +
Authorization-integrity validation
      =
CI-consumable deterministic security result
```

The next problem is no longer only "can the engine detect/validate the property?"

It is:

> Can a normal engineering team run the same property automatically on every relevant change and retain the evidence?

That makes CI integration a distribution and regression-prevention capability, not merely packaging.

## Why not Agent Attack Graph yet

Attack Graph is a major product differentiator, but the graph becomes more valuable after existing observations and authorization results can be collected repeatedly and reproducibly.

Starting the full graph now would add another analysis domain before the current domains have a frictionless adoption path.

## Why not SARIF in this cycle

Runtime/agent authorization findings are not always naturally source-location findings.

Cycle 004 should preserve the native evidence model first.

SARIF can be added later for findings that map cleanly to repository locations.

## Why not Marketplace/v1

The project is still pre-release.

Technical usability of an Action and commercial/stable release are separate gates.

## Independent next candidates after Cycle 004

Potential later cycles include:

- safe intentionally vulnerable MCP reference lab expansion;
- benchmark/corpus harness;
- SARIF/code-scanning adapter;
- baseline standards/rule packs;
- basic topology graph;
- authorization-aware Agent Attack Graph.

Cycle numbering should not be treated as automatic dependency. A later cycle may run in parallel if its prerequisites are already stable.
