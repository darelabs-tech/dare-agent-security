# task-012 — Implement bounded trials, tool-request counts and chain-depth enforcement

**Status:** APPROVED FOR EXECUTION

## Objective
Enforce the approved hard bounds before and during execution.

## Hard bounds
3 default trials; 10 max trials; 8 tool requests/trial; chain depth 3; 24 total requests; 16KiB output/trial; 64KiB total output; 30s/trial; state changes 0; external egress 0.

## Acceptance
- Over-limit input is refused, not clamped upward.
- Counts cannot reset to bypass total limits across trials.
- Stop-on-first-fail works without hiding already-observed violations.
