# task-001 — Reconcile Cycle 002 Interfaces and Pin Standards Snapshot

> Status: **READY FOR REVIEW**
> Depends on: Cycles 001 and 002 merged to `main`

## Objective

Reconcile Cycle 003 planning with the actual merged repository before introducing new code, and persist the exact standards/profile metadata used by the cycle.

## Required work

- inspect merged Cycle 002 crate, module, CLI, lab and redaction APIs;
- reuse existing MCP domain/request representations where they satisfy Cycle 003;
- do not create duplicate discovery/CLI/lab crates because planning names differ from merged names;
- record AuthZEN 1.0, COAZ Framework 1.0 Draft 1, COAZ-MCP 1.0 Draft 1, MCP 2026-07-28 and openid/authzen#603 metadata;
- explicitly note the COAZ-MCP/MCP lifecycle version skew and scope executable vectors to `tools/call`;
- document implementation paths selected for tasks 002–012.

## Invariants

- no implementation begins on guessed Cycle 002 interfaces;
- upstream issue #603 is recorded as an open proposal unless verified otherwise at execution time;
- standards metadata is versioned and machine-readable or centrally testable.

## Tests / proof

- workspace baseline tests remain green;
- a standards metadata unit/fixture test asserts all required references exist;
- implementation notes identify the actual Cycle 002 integration points.

## DONE when

The rest of the cycle can execute without duplicating merged functionality or relying on ambiguous standards versions.
