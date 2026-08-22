# Assessment Profiles

A profile is a named, versioned set of security properties to evaluate
against a target. It's the unit of "what does this assessment actually
check?"

## Built-in profile

`mcp-security-baseline` is the default profile used by product `assess` and
the [Quickstart](../getting-started/quickstart.md). It draws its properties
from the built-in registry
([`schemas/coverage/v1/registry.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/coverage/v1/registry.json)),
which includes properties such as the passive discovery boundary.

## Using a custom profile

`--profile` on `validate coverage` (and the config's `assessment.profile`
field, see [Configuration](../reference/configuration.md)) accepts either a
built-in profile id or a path to a profile JSON conforming to
[`schemas/coverage/v1/profile.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/coverage/v1/profile.schema.json).

## Profile → coverage → gate

```text
profile (what to check)
  ↓
facts (what was observed)
  ↓
coverage report (per-property status)
  ↓
gate (PASS / FAIL / threshold)
```

See [Assessment Coverage](../concepts/assessment-coverage.md) for how
property status and the coverage gate work.
