# task-011 — Define closed principal/delegation/source/trust enums and refusal rules

**Status:** APPROVED FOR EXECUTION
**Dependencies:** task-003, task-004, task-006, task-010

## Objective
Close all identity-security enum surfaces and define fail-closed refusal behavior.

## Acceptance
No free-form enum silently downgrades behavior; unknown principal/delegation/source/trust/mode values refuse or error deterministically.