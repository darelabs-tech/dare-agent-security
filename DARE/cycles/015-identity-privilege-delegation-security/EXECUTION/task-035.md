# task-035 — Run complete compatibility regression and produce final DARE proof

**Status:** APPROVED FOR EXECUTION
**Dependencies:** task-033, task-034

## Objective
Close Cycle 015 only from measured evidence.

## Required evidence
Run fmt, clippy, workspace tests, cargo audit, dedicated Cycle 015 tests, Cycle 003/013/014, Agentic/MCP regressions, docs builds, and the actual local workflow job. Produce `REGRESSION.md` and `PROOF.md` mapping all 67 DESIGN criteria.

## Acceptance
Do not mark DONE or open PR unless every mandatory gate is resolved and the final branch head is pushed. Record residual risks, deviations and exact head/commands/results.