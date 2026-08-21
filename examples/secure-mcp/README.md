# Secure MCP demo (deterministic)

Remediated counterpart of `examples/vulnerable-mcp`.

```bash
cargo run -p dare-agent-security -- assess examples/secure-mcp --offline
cargo run -p dare-agent-security -- report --path examples/secure-mcp
```

Expected gate: **PASS**.
