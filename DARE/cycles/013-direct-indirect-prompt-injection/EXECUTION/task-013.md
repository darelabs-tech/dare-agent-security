# task-013 — Integrate local-synthetic harness with Cycle 009 controls

**Status:** READY FOR EXECUTION

## Objective
Reuse Cycle 009 ROE/budget/kill-switch controlled substrate for LOCAL_SYNTHETIC mode.

## Acceptance
- no second unrestricted runner;
- no remote dynamic/provider execution;
- zero state changes/external egress by default;
- synthetic actions only; requested unauthorized actions are observed, not executed;
- kill-switch/budget evidence preserved.
