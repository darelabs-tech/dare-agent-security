# `doctor`

Diagnose environment, config, privacy, and output paths — without touching
any assessment target.

## Syntax

```bash
dare-agent-security doctor [PATH] [--json]
```

## Arguments

| Argument | Description |
|---|---|
| `PATH` | Project root to diagnose. Default: current directory. |

## Options

| Option | Description |
|---|---|
| `--json` | Emit machine-readable JSON instead of human-readable output. |

## Examples

```bash
dare-agent-security doctor
dare-agent-security doctor ./my-mcp --json
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All checks passed. |
| 1 | Environment or internal error. |
| 2 | A doctor check failed. |
| 3 | Configuration error / usage. |

## When to run it

- Right after installing, to confirm the binary and environment are sane.
- Right after `init`, to confirm the config is valid.
- Whenever `assess` behaves unexpectedly, before filing an issue.

## Security implications

`doctor` never contacts a network target or reads assessment evidence from a
remote source — it only inspects local environment, config, and paths.
