# task-023 — Add confidential/offline and no-remote-target regressions

**Status:** READY FOR EXECUTION

## Objective
Prove Cycle 013 preserves privacy/offline and remote-execution boundaries.

## Acceptance
- replay/simulated/local-synthetic operate offline;
- confidential mode persists no forbidden raw secrets;
- remote URL/provider/credential paths are unavailable/refused;
- network denied remains fail closed;
- tests require no external services.
