# Vulnerable MCP demo (deterministic)

Known authorization/integrity issues for the product quickstart.

## Assess

```bash
cargo run -p dare-agent-security -- assess examples/vulnerable-mcp --offline --confidential
cargo run -p dare-agent-security -- report --path examples/vulnerable-mcp
```

Expected gate: **FAIL**. See `REMEDIATION.md` then reassess `examples/secure-mcp`.
