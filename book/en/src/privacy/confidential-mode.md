# Confidential Mode

```bash
dare-agent-security assess . --confidential
```

Sets classification metadata to `CONFIDENTIAL` (rendered on HTML reports)
and enforces fail-closed privacy: telemetry off, network egress denied.

## Modes compared

| Mode | Telemetry | Network | Behavior |
|---|---|---|---|
| Standard (default) | off | restricted | Product `assess` still never calls remote APIs. |
| Confidential (`--confidential`) | off | denied | Fail-closed egress; classification `CONFIDENTIAL`. |
| Offline (`--offline`) | off | denied | Same fail-closed egress as confidential, without the classification label. |

You can combine both: `--confidential --offline` is the recommended default
for any assessment involving data you don't want to leave your machine.

## What is never collected

- Customer source code as telemetry.
- Raw credentials.
- Crash/analytics uploads.
- A remote model/API dependency for product `assess`.

## Config equivalent

These flags have config-file equivalents under `privacy:` — see
[Configuration](../reference/configuration.md) — so you don't have to
remember to pass them on every invocation.

See also [Offline Mode](offline-mode.md), [Telemetry](telemetry.md), and
[Redaction](redaction.md).
