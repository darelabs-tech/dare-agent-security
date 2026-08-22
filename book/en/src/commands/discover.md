# `discover`

Power-user command. Passive discovery of an explicit MCP target — list-only,
no tool invocation.

## Syntax

```bash
dare-agent-security discover --stdio [--json] [OPTIONS] -- <COMMAND> [ARGS...]
dare-agent-security discover --url <HTTPS-URL> [--json] [OPTIONS]
```

`--stdio` and `--url` are mutually exclusive.

## Key options

| Option | Description |
|---|---|
| `--stdio` | Target is a local stdio MCP server. The program after `--` is `argv[0]`; the scanner never interpolates a shell. |
| `--url <HTTPS-URL>` | Target is a Streamable HTTP MCP server. HTTPS only — credentials in the URL are refused. |
| `--json` | Write one Inventory v1 JSON object to stdout (diagnostics go to stderr). |
| `--target-id <SAFE-ID>` | Explicit safe target identifier for evidence/output naming. |
| `--timeout <DURATION>` | e.g. `30`, `30s`, `5m`, `1h`, `500ms`. |
| `--max-pages <N>` | Cap on paginated list requests. |
| `--max-items <N>` | Cap on total discovered items. |
| `--evidence-dir <PATH>` | Where to write evidence records. |
| `--output-dir <PATH>` | Where to write the inventory output. |
| `--fail-on-inconclusive` | Default `true` — exit non-zero on an inconclusive inventory. |

## Examples

```bash
dare-agent-security discover --stdio -- target/debug/synthetic-mcp
dare-agent-security discover --stdio --json -- target/debug/synthetic-mcp
dare-agent-security discover --url https://mcp.example.com --json
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Complete success (inventory `COMPLETE`, no `INCONCLUSIVE` evidence). |
| 1 | Scanner execution error (transport, timeout, I/O, invalid serialization). |
| 2 | Partial or inconclusive result. |
| 3 | Unsupported or refused target (policy refusal, unsupported protocol revision, invalid target, TLS required, no valid explicit target). |

## Passive boundary

Default discovery is **list-only**. It may send `server/discover` (MCP
`2026-07-28`) or the explicit legacy `initialize` / `notifications/initialized`
handshake (MCP `2024-11-05`), plus `tools/list`, `resources/list`,
`resources/templates/list`, and `prompts/list`. It does **not** invoke
`tools/call`, `resources/read`, or `prompts/get`. See the full policy in
[`docs/passive-policy.md`](https://github.com/darelabs-tech/dare-agent-security/blob/main/docs/passive-policy.md).

## Security implications

No `--token`, `--password`, or `--credential` flags exist anywhere in the
CLI. Never put secrets on the command line — HTTP targets are HTTPS-only and
credentials embedded in the URL are refused outright.
