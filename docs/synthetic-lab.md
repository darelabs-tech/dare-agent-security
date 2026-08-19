# Synthetic MCP lab

`labs/synthetic-mcp` is a deterministic, fictional **vehicle-rental** MCP
server used to prove Cycle 002 discovery. It contains no customer data, live
credentials, or production endpoints.

Binary crate: `synthetic-mcp`.

## Build

```bash
cargo build -p synthetic-mcp
```

The debug binary is `target/debug/synthetic-mcp` (`.exe` on Windows).

## stdio (default)

With no arguments the lab serves MCP over stdin/stdout:

```bash
cargo run -p synthetic-mcp
```

Scan it with the CLI:

```bash
cargo build -p synthetic-mcp
cargo run -p dare-agent-security -- discover --stdio -- target/debug/synthetic-mcp
cargo run -p dare-agent-security -- discover --stdio --json -- target/debug/synthetic-mcp
```

stdio launch uses program + argument vector. Do not wrap the lab in `sh -c`.

## Streamable HTTP (loopback only)

HTTP mode binds **loopback** addresses only (`127.0.0.1` / `::1`). Non-loopback
binds are refused.

```bash
cargo run -p synthetic-mcp -- --http 127.0.0.1:0
```

The process prints `synthetic-mcp listening on http://127.0.0.1:<port>/mcp`
(exact path as implemented). Production CLI `--url` requires **HTTPS**;
cleartext `http://` is refused. Loopback HTTP is for in-crate tests via
`DiscoveryTargetSpec::http_loopback_for_tests`, not for the production CLI.

To scan an HTTP target with the CLI, point `--url` at an HTTPS MCP endpoint you
are authorized to assess. Credentials in the URL are refused.

## What the lab exposes

- Mixed tools (read-only hints, destructive hints, ambiguous/UNKNOWN)
- Resources and prompts (list-only; content exists so `resources/read` /
  `prompts/get` can be proven unused)
- Paginated `tools/list` (page size 3)
- Method trace: JSON-RPC **method names only** (no arguments, headers, or
  secrets)

## Method trace

Set `SYNTHETIC_MCP_TRACE_PATH` to a file path. On shutdown (and during
recording) the lab writes a JSON array of received method names. Cycle 002
tests use this to prove `set(methods) ⊆ Cycle002Allowlist`.

## Tests

```bash
cargo test -p synthetic-mcp
cargo test -p dare-mcp-discovery --test e2e_passive
cargo test -p dare-agent-security --test e2e_matrix
```
