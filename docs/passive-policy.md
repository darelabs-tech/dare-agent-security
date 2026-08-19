# Passive method policy

Default MCP discovery is passive by construction: only an explicit JSON-RPC
allowlist may reach transport. There is **no denylist**. Unknown methods are
refused before dispatch.

Implementation: `crates/dare-mcp-discovery/src/policy.rs` (`DefaultPolicy`,
`PolicyGuardedTransport`).

## Allowlists

Profile is selected from the negotiated/configured MCP revision. Unsupported
revisions fail closed; they do not fall through to guessed semantics.

### Current — MCP `2026-07-28`

| Method | Role |
|---|---|
| `server/discover` | Modern lifecycle (no `notifications/initialized`) |
| `tools/list` | Tool catalog pages |
| `resources/list` | Resource URI catalog pages |
| `resources/templates/list` | Resource template catalog pages |
| `prompts/list` | Prompt name catalog pages |

### Legacy — MCP `2024-11-05`

This is the **only** pre-2026 compatibility path.

| Method | Role |
|---|---|
| `initialize` | Legacy handshake |
| `notifications/initialized` | Legacy handshake completion |
| `tools/list` | Tool catalog pages |
| `resources/list` | Resource URI catalog pages |
| `resources/templates/list` | Resource template catalog pages |
| `prompts/list` | Prompt name catalog pages |

`ping` is not allowlisted on either profile.

## Forbidden in default discovery

These methods are refused before transport. Tool names or arguments in a
hypothetical `tools/call` payload are irrelevant: the method itself never
dispatches.

| Method | Why it is forbidden |
|---|---|
| `tools/call` | Business/state-changing invocation |
| `resources/read` | Protected content retrieval |
| `prompts/get` | Prompt body retrieval |
| `resources/subscribe` | Active subscription |
| `logging/setLevel` | Server mutation |
| `completion/complete` | Non-inventory RPC |
| any other wire name | Unknown; fail closed |

The synthetic lab records received method names (not arguments). Cycle 002
proofs assert:

```text
set(methods_received_by_lab) ⊆ Cycle002Allowlist
```

and explicitly assert absence of `tools/call`, `resources/read`, and
`prompts/get`.

## Scope

The scanner contacts or spawns **only** the operator-supplied target:

- `--stdio -- <program> [args...]` — `argv` vector, no intermediate shell
- `--url <https-url>` — HTTPS only; URL userinfo is refused; redirects are not followed

There is no host/port/tenant enumeration and no credential CLI flags.

## Classification limitation

Passive inventory classifies **declared** tools from metadata. Classification
never executes a tool to confirm behavior. `UNKNOWN` means evidence was
insufficient — not “safe”.
