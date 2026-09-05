# task-007 — Define poisoning/misuse/source/trust closed enums

**Status:** APPROVED FOR EXECUTION

## Objective
Freeze closed taxonomies for Tool Poisoning, Tool Misuse, source classes and trust levels.

## Required work
- Implement approved poisoning and misuse families as typed closed enums.
- Keep Tool Poisoning distinct from Tool Misuse in storage/reporting.
- Unknown enum values must fail closed.

## Acceptance
- No free-form family/source/trust strings drive verdict logic.
- Serialization round-trips deterministically.
- Future Cycle 015/017/019 concepts are not smuggled into this enum set.
