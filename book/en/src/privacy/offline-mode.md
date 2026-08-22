# Offline Mode

```bash
dare-agent-security assess . --offline
```

Denies all network/telemetry egress. This is **fail-closed**: if a code path
would need network access it is refused outright, not silently skipped with
a warning.

## Why fail-closed matters here

For a security tool, a "warning" that still lets an operation proceed is
effectively no control at all. `--offline` (like checksum verification in
the [installers](../getting-started/installation.md)) treats any egress
attempt as a hard stop.

## What still works offline

- All product commands (`init`, `assess`, `report`, `doctor`) against local
  targets and bundled/local fixtures.
- `discover --stdio` against a local process.
- `validate coaz-integrity`, `coverage`, `attack-graph`, and `plan-only` /
  `local-synthetic` modes of `adversarial` and `continuous` — all are
  in-memory or local-fixture based already.

## What's refused

- Any attempted network call from a validation path while `--offline` is
  set — including `authorized-dynamic` adversarial execution, which
  additionally requires a valid ROE regardless of this flag.

See [Confidential Mode](confidential-mode.md) for how this combines with
classification, and [Validation Modes](../concepts/validation.md) for the
full execution ladder.
