# task-033 — Trial ledger and hard limits

**Status:** DONE - REVIEW PASS

Implement bounded trial/run-wide counters for scenario size, observations, retries, output and duration. State changes and external egress remain zero. Limits refuse rather than clamp upward.

## Evidence

`src/trials.rs`. Refuse-never-clamp, and run-wide totals that do not reset between trials — asserted by exhausting the run ceiling across multiple trials rather than by reading the code.
