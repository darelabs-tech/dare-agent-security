# task-008 — Define normalized Tool Observation event model

**Status:** APPROVED FOR EXECUTION

## Objective
Normalize all tool-security observations into closed typed events before verdict evaluation.

## Required work
Support at least the DESIGN-approved channels: tool surface observed, tool selected/requested, tool arguments, tool output observed, chain step, policy decision, objective state and harness error.

## Acceptance
- Raw prose cannot directly decide a verdict.
- Independent facts are emitted independently.
- Event payloads cannot encode executable semantics.
