# Neutral vector matrix (upstream summary)

Synthetic domain: fictional vehicle rental (`rental.quote`). All identifiers use
`*-synthetic-*` prefixes. No customer or production data.

| Vector ID | Authorization input semantics | Mutation | Expected enforcement |
|---|---|---|---|
| COAZ-INTEGRITY-001 | MCP `tools/call` `rental.quote` with unchanged arguments after AuthZEN permit | None | Forward with existing permit |
| COAZ-INTEGRITY-002 | Default mapping binds tool name identity | Change tool name to `rental.confirm` after permit | Re-evaluate or refuse |
| COAZ-INTEGRITY-003 | Declared mapping projects `daily_rate` into authorization request | Change mapped `daily_rate` from 50 to 5000 after permit | Re-evaluate or refuse |
| COAZ-INTEGRITY-004 | Default mapping binds MCP method | Change MCP method after permit | Re-evaluate or refuse |
| COAZ-INTEGRITY-005 | Trusted context claim `role` contributes to authorization | Change mapped `role` after permit | Re-evaluate or refuse |
| COAZ-INTEGRITY-006 | Declared mapping; semantically identical arguments | JSON object key reorder / formatting only | Permit remains bound |
| COAZ-INTEGRITY-007 | Declared mapping; semantically identical mapped fields | Add field not included in mapping projection | Permit remains bound |

Full portable definitions:
[`vectors/coaz-mcp/authorization-integrity/v1/`](../../../vectors/coaz-mcp/authorization-integrity/v1/)

Reference traces:

- Secure PASS (001): [`trace-secure-001.txt`](trace-secure-001.txt)
- Vulnerable FAIL (003): [`trace-vulnerable-003.txt`](trace-vulnerable-003.txt)

Machine-readable results:

- Secure: [`examples/coaz-integrity/secure/result-pass-v1.json`](../../../examples/coaz-integrity/secure/result-pass-v1.json)
- Vulnerable: [`examples/coaz-integrity/vulnerable/result-stale-permit-fail-v1.json`](../../../examples/coaz-integrity/vulnerable/result-stale-permit-fail-v1.json)
