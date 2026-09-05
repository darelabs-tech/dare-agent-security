# task-010 — Implement bounded trial policy and hard maxima

**Status:** READY FOR EXECUTION

## Objective
Enforce approved trial/time/output bounds before and during execution.

## Acceptance
- defaults: 3 trials, stop-on-first-fail;
- hard max trials 10;
- 16384 bytes/trial, 65536 total, 30s/trial maxima;
- input cannot raise hard limits;
- budget exhaustion stops, never auto-expands;
- boundary tests pass.
