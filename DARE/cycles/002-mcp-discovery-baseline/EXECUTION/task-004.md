# task-004 — Version-aware MCP client adapter

> Status: DONE
> Depends on: task-003
> Complexity: HIGH

## Objective
Isolate MCP SDK, lifecycle and transport details behind project-owned interfaces.

## Required implementation
- first-class MCP `2026-07-28` path;
- one explicitly selected pre-2026 compatibility revision;
- stdio transport with executable + argv, no shell by default;
- Streamable HTTP with TLS verification and redirects disabled or scope-checked;
- bounded request/connect/overall timeout and response size;
- negotiated/selected protocol revision recorded.

## Architectural invariants
- all dispatch passes through PassivePolicy;
- no SDK type leaks into canonical inventory models;
- no automatic scope expansion or insecure downgrade;
- unsupported revisions return typed errors.

## Tests
Current lifecycle fixture, legacy fixture, unsupported revision, timeout, redirect refusal/scope check, stdio argv handling and safe error behavior.

## DONE when
Current and legacy protocol details are contained behind the adapter and all integration-level adapter tests pass without violating passive policy.

---

## Execution result

- **Status:** DONE
- **Date:** 2026-08-18
- **Files:** `crates/dare-mcp-discovery/src/adapter.rs`, `adapter_error.rs`, `adapter_http.rs`, `adapter_stdio.rs`, `adapter_session.rs`, `tests/adapter_*.rs`
- **Lifecycles:** `2026-07-28` Discover (`server/discover`); legacy `2024-11-05` Initialize
- **Safety:** TLS required, redirects disabled, stdio argv without shell, PolicyGuardedTransport on outbound methods
