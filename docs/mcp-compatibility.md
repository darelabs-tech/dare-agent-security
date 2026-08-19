# MCP compatibility matrix

Cycle 002 protocol support is **explicit and fail-closed**. The scanner does
not reinterpret a response under a different MCP revision without a defined
profile.

Implementation constants:

- `CURRENT_WIRE_REVISION` = `2026-07-28`
- `LEGACY_WIRE_REVISION` = `2024-11-05`

in `crates/dare-mcp-discovery/src/adapter_session.rs`.

## Matrix

| Revision | Status | Lifecycle | Allowlist extras | Result if selected |
|---|---|---|---|---|
| `2026-07-28` | **First-class** | `server/discover` (Discover mode). Does not send `notifications/initialized`. | `server/discover` + list methods | Inventory with recorded revision |
| `2024-11-05` | **Explicit legacy** | `initialize` + `notifications/initialized` (Initialize mode) | legacy handshake + list methods | Inventory with recorded revision |
| `2025-11-25` | Unsupported | none | — | Typed `UnsupportedRevision`; no guessed profile |
| Any other `YYYY-MM-DD` | Unsupported | none | — | Typed `UnsupportedRevision`; fail closed |

List methods shared by supported profiles: `tools/list`, `resources/list`,
`resources/templates/list`, `prompts/list`.

## Rules

1. **Current first.** MCP `2026-07-28` is the default modern target, including
   optional use of `server/discover` when the server offers it.
2. **Legacy is gated.** `2024-11-05` is the single pre-2026 path. Legacy
   initialize must not leak into the current-profile allowlist (and
   `server/discover` must not leak into the legacy allowlist).
3. **No silent guessing.** Revisions such as `2025-11-25` or future dates are
   refused. The scanner does not map them onto a nearby supported profile.
4. **Fail closed on ambiguity.** Policy and adapter errors are typed. CLI maps
   unsupported/refused targets to exit code `3`.

## Tests

| Claim | Test |
|---|---|
| Current + legacy map without expanding allowlists | `adapter_api::supported_revisions_map_without_expanding_allowlist` |
| Unsupported revision is typed | `adapter_api::unsupported_revision_is_typed_and_does_not_guess` |
| Current E2E uses `server/discover`, not `initialize` | `e2e_passive::streamable_http_current_protocol_is_passive` |
| Legacy E2E uses `initialize` + `notifications/initialized` | `e2e_passive::legacy_initialize_scenario_is_passive` |
| Cross-profile method isolation | `policy_guard::current_profile_refuses_legacy_lifecycle_and_legacy_refuses_discover` |
