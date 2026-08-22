# `init`

Initialize a local product config and artifact store.

## Syntax

```bash
dare-agent-security init [PATH] [--force] [--name NAME] [--confidential]
```

## Arguments

| Argument | Description |
|---|---|
| `PATH` | Project root to initialize. Default: current directory. |

## Options

| Option | Description |
|---|---|
| `--force` | Overwrite an existing config. |
| `--name NAME` | Project name override (otherwise inferred). |
| `--confidential` | Initialize with confidential/offline fail-closed defaults. |

## Examples

```bash
dare-agent-security init
dare-agent-security init ./my-mcp --name my-mcp --confidential
dare-agent-security init . --force
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Config written successfully. |
| 1 | Environment or internal error. |
| 2 | — (not applicable to `init`) |
| 3 | Configuration or usage error (e.g. config already exists without `--force`). |

## Generated artifacts

A config file at the target root (search order and schema: see
[Configuration](../reference/configuration.md)) and the
`.dare-security/` artifact store directory.

## Security implications

`--confidential` sets fail-closed privacy defaults from the start (telemetry
off, network denied) rather than relying on you remembering to pass
`--confidential`/`--offline` on every later `assess`.
