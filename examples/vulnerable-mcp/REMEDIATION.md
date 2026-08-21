# Remediation for vulnerable-mcp

1. Require per-operation authorization before tool execution.
2. Reject tool-name mutation between authorize and execute (execution integrity).
3. Do not forward stale permits across mutating operations.

After applying these controls, assess `examples/secure-mcp` and expect gate **PASS**.
