# dare-mcp-discovery

Passive MCP discovery library for DARE Agent Security.

This crate inventories an operator-supplied MCP target without invoking business
tools or reading protected content. It is a library. The CLI binary lives in
`dare-agent-security` (`crates/dare-agent-security-cli`).

## Architecture

```text
dare-agent-security (CLI)
        |
        v
dare-mcp-discovery
        |
        v
dare-security-evidence
```

- **CLI** parses explicit `--stdio` / `--url` targets, prints human or JSON
  output, and maps completeness/errors onto documented exit codes.
- **Discovery** owns protocol adapters, the passive method allowlist, bounded
  enumeration, conservative tool classification, redaction, Inventory v1, and
  the Cycle 001 evidence bridge.
- **Evidence** stays MCP-agnostic. This crate may depend inward on
  `dare-security-evidence`. The evidence crate must not depend on discovery or
  the CLI.

Protocol SDK types (`rmcp`) stay behind crate-owned snapshots. They must not
leak into the public inventory JSON contract.

## Inventory schema

| Artifact | Path |
|---|---|
| JSON Schema v1 | [`schemas/discovery/v1/inventory.schema.json`](../../schemas/discovery/v1/inventory.schema.json) |
| `$id` | `https://darelabs.tech/schemas/discovery/v1/inventory.schema.json` |
| Public fixtures | [`examples/discovery/`](../../examples/discovery/) |

The committed schema file is normative. Validation **must not** fetch the `$id`
URL. See [docs/inventory-v1.md](../../docs/inventory-v1.md).

## Passive policy

Outbound JSON-RPC methods are **allowlisted**. There is no denylist: unknown
methods are refused before transport dispatch.

Forbidden in default discovery:

- `tools/call`
- `resources/read`
- `prompts/get`

See [docs/passive-policy.md](../../docs/passive-policy.md) and
[docs/mcp-compatibility.md](../../docs/mcp-compatibility.md).

## Classification `UNKNOWN` rule

Tool classes are `READ_ONLY`, `STATE_CHANGING`, `DESTRUCTIVE`, or `UNKNOWN`.

- Self-reported MCP annotations are **untrusted hints**. They are stored and
  may be used as provenance (`PROTOCOL_ANNOTATION`); they are never treated as
  proof of actual security behavior.
- Name and description heuristics are recorded as indicators only. They cannot
  independently produce `READ_ONLY`.
- Missing, weak, or conflicting metadata resolves to `UNKNOWN` with source
  `INSUFFICIENT_METADATA`. Ambiguity is never guessed-safe.

## License

Apache-2.0.
