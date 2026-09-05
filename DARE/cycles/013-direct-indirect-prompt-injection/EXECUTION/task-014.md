# task-014 — Build direct prompt-injection corpus and paired fixtures

**Status:** READY FOR EXECUTION

## Objective
Create versioned direct-injection corpus entries and secure/vulnerable paired fixtures.

## Acceptance
- cover goal override, instruction override, role confusion, protected-data request, unauthorized action, instruction smuggling;
- use synthetic harmless payloads/canaries;
- secure/vulnerable pairs produce expected deterministic observations;
- no real secrets/targets.
