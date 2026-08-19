# task-008 — Cycle 001 evidence bridge

> Status: DONE
> Depends on: task-002, task-003, task-006, task-007
> Complexity: MEDIUM

## Objective
Convert deterministic discovery/baseline observations into the existing generic `SecurityEvidence` v1 contract without modifying the evidence schema.

## Initial vectors
- `MCP-DISCOVERY-001` protocol negotiation/selection;
- `MCP-DISCOVERY-002` passive-method policy enforcement;
- `MCP-DISCOVERY-003` inventory completeness/partial status;
- `MCP-DISCOVERY-004` credential redaction property.

## Required implementation
Each evidence record references safe target identity, inventory/run revision, expected + observed outcome, deterministic verdict, mappings/rationale where applicable, hashes and redaction metadata.

## Invariants
- no MCP-specific field added to `dare-security-evidence`;
- no raw credentials;
- uncertainty becomes INCONCLUSIVE/ERROR where appropriate, never fabricated PASS;
- evidence validates through Cycle 001 structural and semantic validators.

## Tests
PASS/FAIL/INCONCLUSIVE cases where meaningful; bridge output round-trips and validates against evidence v1.

## DONE when
All initial bridge vectors emit valid evidence and the evidence crate remains unchanged in domain scope.
