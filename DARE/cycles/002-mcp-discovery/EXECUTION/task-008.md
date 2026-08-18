# task-008 — Implement Cycle 001 evidence bridge

## Goal
Convert deterministic discovery observations into the existing SecurityEvidence v1 contract without coupling the evidence kernel to MCP.

## Required implementation
- Add discovery-side adapters for `MCP-DISCOVERY-001..004`.
- Reference sanitized inventory artifacts/digests rather than embedding arbitrary raw responses.
- Derive expected/observed outcomes and verdicts through Cycle 001 validation/comparison APIs.
- Preserve vector/schema versions and standards metadata.
- Emit explicit INCONCLUSIVE/ERROR rather than PASS when discovery information is insufficient.

## Required tests
PASS passive-policy proof; partial inventory evidence; redaction property; protocol negotiation result; invalid/contradictory evidence rejected by existing kernel.

## Gates
Standard workspace gates plus Cycle 001 contract tests unchanged.

## DONE
Discovery can emit valid SecurityEvidence v1 records and no modification to the generic evidence schema is required.