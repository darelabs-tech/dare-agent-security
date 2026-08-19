# task-003 — Passive MCP method policy

> Status: DONE
> Depends on: task-001
> Complexity: HIGH

## Objective
Guarantee that discovery is passive by construction through a centralized allowlist gate.

## Required implementation
- define the version-aware set of passive methods;
- route every outbound discovery request through one policy guard;
- unknown/non-allowlisted methods return typed refusal before transport;
- refusal errors expose method metadata only.

## Must refuse
`tools/call`, `resources/read`, `prompts/get`, arbitrary extension methods and any business/action operation not explicitly approved for passive discovery.

## Tests
Use a fake/recording transport to prove refused methods produce zero dispatches. Cover allowed current-protocol list/discover methods and bounded legacy lifecycle methods.

## Security invariants
Allowlist, never denylist. No arguments/secrets echoed on refusal. No bypass path around the guard.

## DONE when
All outbound discovery entrypoints are policy-gated and forbidden-method tests prove zero transport activity.

---

## Execution result

- **Status:** DONE
- **Date:** 2026-08-18
- **Files:** `crates/dare-mcp-discovery/src/policy.rs`, `policy_error.rs`, `policy_transport.rs`, `tests/policy_guard.rs`
- **Profiles:** MCP `2026-07-28` (includes `server/discover`) and legacy `2024-11-05` (`initialize` + `notifications/initialized`)
- **Proof:** forbidden methods including `tools/call`, `resources/read`, `prompts/get` produce zero `RecordingTransport` dispatches
