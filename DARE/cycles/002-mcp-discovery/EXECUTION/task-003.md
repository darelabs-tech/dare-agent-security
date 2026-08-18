# task-003 — Implement passive MCP method policy

## Goal
Make passive-only behavior an enforced runtime invariant rather than a convention.

## Required implementation
- Centralize every outbound discovery method behind `PassivePolicy`.
- Maintain an explicit version-aware allowlist for server discovery, collection list methods, and legacy lifecycle operations needed for compatibility.
- Unknown or extension methods fail closed.
- Refuse `tools/call`, `resources/read`, `prompts/get`, completion, sampling/elicitation and state-changing task operations.
- Refusal occurs before transport dispatch.
- Typed refusal errors expose safe method metadata only.

## Required tests
Use a recording fake transport. Attempt every allowed method plus forbidden methods and an unknown extension. Assert forbidden requests produced zero dispatches.

## Gates
Standard workspace gates.

## DONE
There is exactly one enforceable outbound policy boundary and tests prove forbidden operations cannot cross it.