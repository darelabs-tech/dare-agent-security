# COAZ integrity — CLI

Cycle 003 is exposed through the merged validation CLI:

```bash
dare-agent-security validate coaz-integrity [OPTIONS]
```

Built from `crates/dare-agent-security-cli`; library logic lives in
`crates/dare-coaz-integrity`.

## Commands

### Single fixture

```bash
cargo run -p dare-agent-security -- validate coaz-integrity --fixture COAZ-INTEGRITY-003
```

### All fixtures (secure mode)

```bash
cargo run -p dare-agent-security -- validate coaz-integrity --all
```

### JSON output (stdout only)

```bash
cargo run -p dare-agent-security -- validate coaz-integrity --all --json
```

Single fixture: one JSON object. `--all`: JSON array of seven results.
Diagnostics go to stderr; stdout stays machine-clean on errors.

### Vulnerable reference mode

```bash
cargo run -p dare-agent-security -- validate coaz-integrity --fixture COAZ-INTEGRITY-003 \
  --reference-mode vulnerable --json
```

Proves stale-permit FAIL for mutation vectors. Synthetic fixtures only — no
`--url` or `--stdio` targets.

### Evidence artifacts

```bash
cargo run -p dare-agent-security -- validate coaz-integrity --fixture COAZ-INTEGRITY-001 \
  --evidence-dir ./out
```

Writes:

- `{vector_id}.result.json` — full `VectorResult`
- `{vector_id}.evidence.json` — Cycle 001 `SecurityEvidence`

## Flags

| Flag | Description |
|---|---|
| `--fixture <ID>` | Run one built-in vector (e.g. `COAZ-INTEGRITY-001`) |
| `--all` | Run all seven built-in vectors |
| `--json` | Emit JSON to stdout |
| `--reference-mode <MODE>` | `secure` (default), `secure-refuse`, or `vulnerable` |
| `--evidence-dir <PATH>` | Write result + evidence JSON files |

`--fixture` and `--all` are mutually exclusive.

## Exit codes

Documented in [`crates/dare-agent-security-cli/EXIT.md`](../crates/dare-agent-security-cli/EXIT.md).

| Code | Meaning |
|---|---|
| 0 | All executed vectors returned verdict `PASS` |
| 1 | Harness error (load, execution, serialization, I/O) |
| 2 | At least one vector returned `FAIL` or `INCONCLUSIVE` |
| 3 | Usage error or safety refusal (unknown fixture, invalid flags) |

Vulnerable mode on mutation vectors exits **2** (expected FAIL proof).

## Built-in fixture IDs

```text
COAZ-INTEGRITY-001
COAZ-INTEGRITY-002
COAZ-INTEGRITY-003
COAZ-INTEGRITY-004
COAZ-INTEGRITY-005
COAZ-INTEGRITY-006
COAZ-INTEGRITY-007
```

## Discover unchanged

`discover` remains a separate subcommand with its own passive boundary and
exit codes. Cycle 003 does not add credential flags or arbitrary target URLs
to `validate coaz-integrity`.
