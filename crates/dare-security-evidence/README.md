# dare-security-evidence

Protocol-neutral, versioned **security evidence** kernel for DARE Agent Security.

This crate is the Cycle 001 contract: a machine-readable record of a deterministic
security or conformance vector. It is a library only. It does not implement MCP,
AuthZEN, COAZ, CLI, network clients, databases, or customer-specific models.

## Canonical schema

| Artifact | Path |
|---|---|
| JSON Schema v1 | [`schemas/evidence/v1/evidence.schema.json`](../../schemas/evidence/v1/evidence.schema.json) |
| `$id` | `https://darelabs.tech/schemas/evidence/v1/evidence.schema.json` |
| Public fixtures | [`examples/evidence/`](../../examples/evidence/) |

The committed schema file is normative. Validation **must not** fetch the `$id` URL.
Non-Rust implementations should load that file from the repository (or a tagged
release) and validate locally with any Draft 2020-12 JSON Schema library.

## Versioning

- Wire version is `MAJOR.MINOR.PATCH` on `schema.version`.
- This crate accepts **major version 1** only (`1.x.y`).
- Unknown majors **fail closed**. The kernel does not guess future semantics.
- Additive optional fields may appear within major 1; they must not change existing
  required meaning.

## Verdicts

| Verdict | Meaning |
|---|---|
| `PASS` | Observed behavior satisfies the vector's deterministic expectation. |
| `FAIL` | Observed behavior violates the vector's deterministic expectation. |
| `INCONCLUSIVE` | Execution completed but evidence is insufficient to decide. Never treated as `PASS`. |
| `ERROR` | Evaluation/infrastructure failure. Not a security success or failure. |

`INCONCLUSIVE` and `ERROR` are never silently converted into `PASS`.

A caller-supplied contradictory record such as `expected=DENY`, `observed=ALLOW`,
`verdict=PASS` is rejected.

## Validation layers

1. **Structural** — JSON Schema (`additionalProperties: false` at the top level,
   enums, digest/timestamp formats). Independently usable without Rust.
2. **Semantic** — `dare_security_evidence::validate`: supported major, non-empty
   identifiers, timestamp order, hash coherence, verdict consistency, redaction
   metadata, secret-safety heuristics.

Both layers are offline.

## Redaction

`redaction` is mandatory on every record.

- `NONE_REQUIRED` means the producer determined that **no** sensitive value needed
  redaction. It does **not** mean redaction was skipped.
- Generic maps (`operation.attributes`, `authorization_context.context_attributes`,
  `extensions`) reject high-risk key names (`password`, `secret`, `token`,
  `api_key`, `private_key`, `authorization`) and representative secret-like values.
- Heuristics are defense-in-depth, not complete secret discovery.
- Typed errors never echo rejected values.

## Compatibility

Released public fixtures in `examples/evidence/` are the compatibility corpus:
deserialize → JSON Schema → semantic validate → serialize → deserialize → equality.

Rust API may evolve before 1.0; the JSON contract for a tagged `1.x` schema should
remain independently validatable.
