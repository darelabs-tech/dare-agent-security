# task-002 — Implement Inventory v1 model and JSON Schema

## Goal
Define the canonical, versioned, machine-readable MCP discovery inventory contract.

## Required implementation
- Implement `DiscoveryInventory` and bounded wire enums in `dare-mcp-discovery`.
- Commit `schemas/discovery/v1/inventory.schema.json` using JSON Schema Draft 2020-12.
- Add offline structural validation and independent semantic validation.
- Add `examples/discovery/complete.json` and `partial.json` using synthetic data.
- Reject unsupported major versions and invalid complete/partial warning combinations.
- Keep raw credentials and customer concepts out of the model.

## Required tests
Valid round-trip; missing required field; unknown top-level field; unsupported major; malformed timestamp/hash; duplicate identities; invalid classification/source combination; partial without reason; secret-like forbidden field.

## Gates
Standard workspace gates plus schema/fixture contract tests.

## DONE
Both public fixtures validate structurally and semantically, invalid cases fail deterministically, and schema validation requires no network.