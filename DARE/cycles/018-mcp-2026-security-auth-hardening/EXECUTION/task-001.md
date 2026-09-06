# task-001 — Freeze post-Cycle-017 baseline and compatibility contracts

**Status:** DONE — REVIEW PASS

Freeze `main @ f5906e8b24679b7affffcdc9db5d6116ba9b045d` as the Cycle 018 baseline. Record inherited contracts from Cycles 001–017, especially MCP 2026 discovery, Cycle 003 final-operation binding, Cycle 015 identity semantics, coverage math, CLI/artifact compatibility and PR-open-only CI behavior. Do not rewrite prior-cycle semantics.

## Evidence

`DARE/cycles/018-mcp-2026-security-auth-hardening/BASELINE.md`, measured on this branch at
`eb4721b5` rather than quoted from a previous cycle.

- `cargo test --workspace` → **2442 passing, 0 failing**; per-crate table recorded.
- Inventory: v1 MCP properties 10, v2 Agentic properties 40, Agentic risk families 10,
  profiles 7, CI jobs 15.
- Inherited contracts recorded per cycle (001 evidence, 002 revision constants, 003
  binding, 006 denominators, 009 budgets, 015 identity), each naming the concrete symbol
  Cycle 018 reuses rather than the idea.
- §4 records the Cycle 017 replay-binding defect fixed in `940b920` on `main`, generalised
  to the rule Cycle 018 inherits: observed evidence is evidence, never the authority that
  defines what was approved.
- CI trigger recorded verbatim as `pull_request` / `branches: [main]` / `types: [opened]`.
