# task-009 — Deterministic synthetic MCP lab

> Status: PENDING REVIEW
> Depends on: task-004, task-005, task-006
> Complexity: HIGH

## Objective
Provide a public, deterministic, synthetic MCP target for discovery, compatibility and safety proofs.

## Required capabilities
- one read-only tool;
- one state-changing tool;
- one destructive tool;
- one ambiguous tool;
- resources;
- one resource template;
- prompts;
- deterministic pagination;
- current MCP protocol scenario;
- selected legacy scenario;
- method trace capture for every received RPC method.

## Data policy
Synthetic-only identifiers/data. No customer names, endpoints, credentials, proprietary schemas or findings.

## Security invariants
Lab business tools must not be executed by discovery tests. Method-trace storage must contain method names/metadata only where possible and no canary credentials.

## Tests
Lab starts deterministically, exposes the declared catalog, paginates predictably and records received method names reproducibly.

## DONE when
The lab can drive both adapter and CLI integration tests and provides trustworthy method traces for task-011.
