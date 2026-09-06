# task-035 — Simulated adapter

**Status:** DONE - REVIEW PASS

Implement deterministic simulated observations from approved scenario data only. No network/provider calls and no adapter-provided final verdict.

## Evidence

`src/simulated.rs`. Stages routing metadata only; every other behaviour comes from the scenario's own declared evidence, so no staged attack can widen what was approved.
