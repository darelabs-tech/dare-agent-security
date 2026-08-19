# COAZ-MCP authorization-to-execution integrity (Cycle 003)

Cycle 003 adds deterministic conformance vectors for the authorization-to-use
boundary described in [OpenID AuthZEN issue #603](https://github.com/openid/authzen/issues/603).
It proves whether a PEP re-evaluates or refuses when mapping-relevant semantics
change after a permit, and whether an intentionally vulnerable reference PEP
forwards stale permits.

This is **not** a full COAZ-MCP implementation. Vectors run against built-in
synthetic fixtures only — no production endpoints, credentials, or customer data.

## Problem summary

An authorization decision is only meaningful for the operation that produced it.
A PEP can map an MCP `tools/call` into AuthZEN, receive `permit`, and still
violate the boundary if middleware changes mapping-relevant semantics before
forwarding:

```text
MCP tools/call (daily_rate=50)
        → COAZ mapping → AuthZEN PERMIT
        → post-decision mutation (daily_rate=5000)
        → forward with stale permit   ← integrity failure
```

Issue #603 proposes an additional authorization-to-execution binding property.
That proposal is **OPEN_PROPOSAL** — not normative COAZ-MCP text until upstream
accepts it. See [coaz-integrity-standards.md](coaz-integrity-standards.md).

## Documentation map

| Topic | Document |
|---|---|
| Security property, PEP flow, safety boundary | [coaz-integrity-policy.md](coaz-integrity-policy.md) |
| Vector matrix 001–007, secure/vulnerable traces | [coaz-integrity-vectors.md](coaz-integrity-vectors.md) |
| CLI usage, exit codes, JSON output | [coaz-integrity-cli.md](coaz-integrity-cli.md) |
| Standards snapshot, MCP/COAZ lifecycle skew | [coaz-integrity-standards.md](coaz-integrity-standards.md) |

## Quick start

```bash
cargo build -p dare-agent-security
cargo run -p dare-agent-security -- validate coaz-integrity --all
cargo run -p dare-agent-security -- validate coaz-integrity --fixture COAZ-INTEGRITY-003 --json
```

Secure mode (default) expects verdict `PASS` for all seven vectors (exit 0).
Vulnerable reference mode proves stale-permit forwarding for mutation vectors
002–005 (exit 2, verdict `FAIL`):

```bash
cargo run -p dare-agent-security -- validate coaz-integrity --all --reference-mode vulnerable
```

Write machine-readable artifacts to a directory:

```bash
cargo run -p dare-agent-security -- validate coaz-integrity --fixture COAZ-INTEGRITY-001 \
  --evidence-dir /tmp/coaz-evidence
```

## Artifacts

| Kind | Location |
|---|---|
| Vector definitions | [`vectors/coaz-mcp/authorization-integrity/v1/`](../vectors/coaz-mcp/authorization-integrity/v1/) |
| Vector JSON Schema | [`schemas/vectors/coaz-integrity/v1/vector.schema.json`](../schemas/vectors/coaz-integrity/v1/vector.schema.json) |
| Result JSON Schema | [`schemas/vectors/coaz-integrity/v1/result.schema.json`](../schemas/vectors/coaz-integrity/v1/result.schema.json) |
| Secure result example | [`examples/coaz-integrity/secure/`](../examples/coaz-integrity/secure/) |
| Vulnerable FAIL example | [`examples/coaz-integrity/vulnerable/`](../examples/coaz-integrity/vulnerable/) |
| Evidence examples | [`examples/coaz-integrity/evidence/`](../examples/coaz-integrity/evidence/) |
| Standards snapshot fixture | [`examples/coaz-integrity/cycle003-standards-v1.json`](../examples/coaz-integrity/cycle003-standards-v1.json) |
| Library crate | [`crates/dare-coaz-integrity/`](../crates/dare-coaz-integrity/) |
| Acceptance proof matrix | [`DARE/cycles/003-coaz-authorization-integrity/PROOF.md`](../DARE/cycles/003-coaz-authorization-integrity/PROOF.md) |
| Upstream contribution package | [`DARE/cycles/003-coaz-authorization-integrity/upstream/`](../DARE/cycles/003-coaz-authorization-integrity/upstream/) |

Schemas and fixtures are validated **offline** from committed files. Do not
fetch `$id` URLs from the network.

## Semantic equality

Binding compares **normalized semantic values**, not raw JSON bytes. Object key
order and formatting changes must not invalidate a permit (vector 006). Mapped
argument or identity changes must change the binding (vectors 002–005).

## Upstream contribution

Neutral vector material suitable for human-reviewed discussion in OpenID AuthZEN
is packaged under
[`DARE/cycles/003-coaz-authorization-integrity/upstream/`](../DARE/cycles/003-coaz-authorization-integrity/upstream/).
Do not treat that package as an automatic upstream PR or IPR submission.
