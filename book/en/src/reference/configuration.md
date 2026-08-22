# Configuration

## Schema

[`schemas/product/v1/config.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/product/v1/config.schema.json)

## Search order

Under the target root, in order:

1. `dare-security.yaml` / `.yml` / `.json`
2. `.dare-security/config.yaml` / `.yml` / `.json`

`--config PATH` on `assess` overrides this search entirely.

## Fields

```yaml
version: "1"
project:
  name: my-agent            # required
assessment:
  profile: mcp-security-baseline
privacy:
  mode: standard             # standard | confidential
  telemetry: false
  network: restricted        # restricted | denied | allowlisted
  offline: false
  retention_days: 30
reporting:
  formats: [html, json]
classification:
  level: internal
  distribution: []
  publication_allowed: false
```

| Field | Type | Notes |
|---|---|---|
| `version` | string | Must match `^1(\..*)?$`. |
| `project.name` | string | Required, non-empty. |
| `assessment.profile` | string | Built-in profile id or path — see [Profiles](../assessments/profiles.md). |
| `privacy.mode` | `standard` \| `confidential` | |
| `privacy.telemetry` | boolean | Default `false`. |
| `privacy.network` | `restricted` \| `denied` \| `allowlisted` | |
| `privacy.offline` | boolean | |
| `privacy.retention_days` | integer ≥ 1, or `null` | Documents intended local retention (default 30). Operators own actual deletion of run directories. |
| `reporting.formats` | array of `html` \| `json` | |
| `classification.level` | string | Free-form label rendered on reports. |
| `classification.distribution` | array of strings | |
| `classification.publication_allowed` | boolean | |

Additional properties are rejected at every level (`additionalProperties:
false`) — a typo'd key fails config loading rather than being silently
ignored.

## Defaults

`init` writes: telemetry off, network `restricted`, profile
`mcp-security-baseline`, formats `[html, json]`.
