# dare-coaz-integrity

Deterministic COAZ-MCP authorization-to-execution integrity harness for DARE
Agent Security (Cycle 003).

Tests whether a reference PEP re-evaluates or refuses when mapping-relevant
semantics change after a permit, and whether an intentionally vulnerable
reference PEP forwards stale permits. Built-in synthetic fixtures only.

## Architecture

```text
dare-agent-security-cli
        |
        v
dare-coaz-integrity
        |
        v
dare-security-evidence
```

- **CLI** (`validate coaz-integrity`) parses flags, maps verdicts to exit codes,
  and optionally writes evidence artifacts.
- **Integrity harness** owns vector/result contracts, semantic canonicalization,
  binding, projectors, in-process PDP, mutation, reference PEP gateway, and
  synthetic execution sink.
- **Evidence** stays MCP/COAZ-agnostic. This crate emits Cycle 001
  `SecurityEvidence` with a `dare.coaz.integrity` extension.

Cycle 002 discovery (`dare-mcp-discovery`) must **not** depend on this crate.

## Public modules

| Module | Responsibility |
|---|---|
| `vector` / `vector_validation` | Portable vector definitions |
| `result` / `result_validation` | Versioned execution results |
| `canonical` | Semantic normalization and digests |
| `binding` | `BindingMaterialV1` authorization binding |
| `projector` | Default and declared synthetic mappings |
| `pdp` | Deterministic in-process policy decisions |
| `mutation` | Controlled post-permit changes |
| `sink` / `enforcement` | Reference PEP gateway and synthetic sink |
| `runner` | Built-in vector loader and executor |
| `evidence_bridge` | Cycle 001 evidence emission |
| `standards` | Versioned standards snapshot metadata |
| `secret_safety` | Canary and prohibited-field checks |

## Schemas and fixtures

| Artifact | Path |
|---|---|
| Vector JSON Schema v1 | [`schemas/vectors/coaz-integrity/v1/vector.schema.json`](../../schemas/vectors/coaz-integrity/v1/vector.schema.json) |
| Result JSON Schema v1 | [`schemas/vectors/coaz-integrity/v1/result.schema.json`](../../schemas/vectors/coaz-integrity/v1/result.schema.json) |
| Built-in vectors | [`vectors/coaz-mcp/authorization-integrity/v1/`](../../vectors/coaz-mcp/authorization-integrity/v1/) |
| Examples | [`examples/coaz-integrity/`](../../examples/coaz-integrity/) |

Validation uses committed schema files offline. Do not fetch `$id` URLs.

## Running vectors

Library API:

```rust
use dare_coaz_integrity::{execute_builtin_vector, RunOptions, ReferencePepMode};

let result = execute_builtin_vector("COAZ-INTEGRITY-003", RunOptions::default())?;
```

CLI (preferred for operators):

```bash
cargo run -p dare-agent-security -- validate coaz-integrity --all
```

See [docs/coaz-integrity-cli.md](../../docs/coaz-integrity-cli.md).

## Tests

```bash
cargo test -p dare-coaz-integrity
```

Key suites:

- `tests/e2e_integrity.rs` — secure/vulnerable trace proof, canary safety
- `tests/vector_result_contract.rs` — offline schema validation
- `tests/standards_snapshot.rs` — pinned standards metadata

Full workspace gates:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
```

## Documentation

- Overview: [docs/coaz-integrity.md](../../docs/coaz-integrity.md)
- Policy / PEP flow: [docs/coaz-integrity-policy.md](../../docs/coaz-integrity-policy.md)
- Vector matrix: [docs/coaz-integrity-vectors.md](../../docs/coaz-integrity-vectors.md)
- Acceptance proof: [DARE/cycles/003-coaz-authorization-integrity/PROOF.md](../../DARE/cycles/003-coaz-authorization-integrity/PROOF.md)

## Safety

- No network I/O during vector execution
- No raw credentials in artifacts, logs, or errors
- Vulnerable mode limited to built-in synthetic fixtures
- Issue #603 recorded as `OPEN_PROPOSAL`, not normative COAZ-MCP text
