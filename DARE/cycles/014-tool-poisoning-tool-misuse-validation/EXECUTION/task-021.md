# task-021 — Implement independent multi-violation capture and secret/redaction hygiene

**Status:** APPROVED FOR EXECUTION

## Objective
Preserve every independently observed violation and prevent secrets/canaries from reaching persisted artifacts.

## Acceptance
- One classification never masks another.
- TOOL-LAB-019 captures simultaneous violations independently.
- Credential/canary detection scans bounded full values and redacts before persistence.
