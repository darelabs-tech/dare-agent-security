# Discovery Inventory v1

Machine-readable contract for a passive MCP discovery scan.

## Canonical artifacts

| Artifact | Path |
|---|---|
| JSON Schema (normative) | [`schemas/discovery/v1/inventory.schema.json`](../schemas/discovery/v1/inventory.schema.json) |
| Schema `$id` | `https://darelabs.tech/schemas/discovery/v1/inventory.schema.json` |
| Record `schema.id` | `https://darelabs.tech/schemas/discovery` |
| Complete fixture | [`examples/discovery/complete.json`](../examples/discovery/complete.json) |
| Partial fixture | [`examples/discovery/partial.json`](../examples/discovery/partial.json) |
| Rust model | `crates/dare-mcp-discovery/src/inventory.rs` |

The committed schema file is the source of truth. Validators **must** load that
file (or a tagged release copy) and **must not** fetch `$id` from the network.

## Versioning

- Wire version is `MAJOR.MINOR.PATCH` on `schema.version`.
- This release accepts **major version 1** only (`1.x.y`). Current fixtures use `1.0.0`.
- Unknown majors **fail closed**. The library does not guess future semantics.
- Additive optional fields may appear within major 1; they must not change
  existing required meaning.
- Top-level `additionalProperties` is `false`. Unknown fields fail structurally.

## Completeness

`completeness` is required. There is no implicit default.

| Value | Meaning |
|---|---|
| `COMPLETE` | Enumeration finished within configured bounds. |
| `PARTIAL` | Enumeration stopped early (page/item/byte/timeout/malformed metadata) and remaining observations are still machine-readable. |

A `COMPLETE` inventory must not carry a pagination-limit warning. A `PARTIAL`
inventory remains schema-valid.

## Validation layers

1. **Structural** — JSON Schema (Draft 2020-12), including format checks such as `date-time`. Independently usable without Rust.
2. **Semantic** — `dare_mcp_discovery::validate`: canonical `schema.id`, supported major, non-empty identifiers, hash shape, input-schema bounds, completeness coherence, redaction metadata, secret-safety heuristics.

Both layers are offline. Typed errors include JSON Pointer paths and reason codes; rejected values are not echoed.

## Determinism

Catalog arrays are normalized by sorting:

- tools by `name`
- resources by `uri`
- resource templates by `uri_template`
- prompts by `name`

Run-scoped fields such as `generated_at` are excluded from catalog equality checks. Two unchanged synthetic scans must produce the same catalog names.

## Secrets and identity

The contract has no credential fields (`password`, `token`, `authorization`, `api_key`, `private_key`). Target identity is an operator-safe `id` plus an optional sanitized `endpoint_fingerprint` (no userinfo, query, or fragment).

`redaction` is mandatory on every record.

## Related docs

- [Passive method policy](passive-policy.md)
- [MCP compatibility](mcp-compatibility.md)
- [Synthetic lab](synthetic-lab.md)
