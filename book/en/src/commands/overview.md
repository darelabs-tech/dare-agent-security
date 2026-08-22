# Commands Overview

```text
dare-agent-security init [PATH] [--force] [--name NAME] [--confidential]
dare-agent-security assess <PATH> [--confidential] [--offline] [--config PATH] [--run ID] [--json]
dare-agent-security report [--path PATH] [--run ID] [--refresh] [--json]
dare-agent-security doctor [PATH] [--json]
```

These four **product commands** are the primary, stable v1 surface — this is
what most users need.

```text
dare-agent-security discover ...
dare-agent-security validate <coaz-integrity|coverage|benchmark|attack-graph|adversarial|continuous> ...
dare-agent-security ci write-result ...
```

These **power-user commands** remain available and are what the product
commands orchestrate under the hood. They expose finer-grained control for
advanced workflows and CI adapters.

Binary name: `dare-agent-security` (some docs/aliases refer to it as
`dare-security`).

Always verify this reference against the binary itself when in doubt — it's
the single source of truth:

```bash
dare-agent-security --help
dare-agent-security assess --help
dare-agent-security validate --help
```

See [Exit Codes](../reference/exit-codes.md) for the full table, and
[Generated Artifacts](../reference/artifacts.md) for what each command
writes to disk.
