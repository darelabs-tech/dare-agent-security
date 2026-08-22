# Passive Discovery

Passive discovery is the default and safest starting point for any target:
list what exists, without invoking anything.

## What "passive" means here

`discover` may send `server/discover` (MCP `2026-07-28`) or the explicit
legacy `initialize` / `notifications/initialized` handshake (MCP
`2024-11-05`), plus `tools/list`, `resources/list`,
`resources/templates/list`, and `prompts/list`.

It does **not** invoke `tools/call`, `resources/read`, or `prompts/get` —
nothing that could have a side effect or read protected content.

## Why start here

Passive discovery gives you an inventory (server metadata, tools, resources,
prompts) that later stages build on: coverage evaluation needs facts,
attack-graph modeling needs nodes and edges, and adversarial validation needs
a target shape to test against. Doing this passively first means you get a
real picture before opting into anything more active.

## Full policy

See [`docs/passive-policy.md`](https://github.com/darelabs-tech/dare-agent-security/blob/main/docs/passive-policy.md)
for the complete, authoritative boundary definition, and
[`discover`](../commands/discover.md) for the command reference.
