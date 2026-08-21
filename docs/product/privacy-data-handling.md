# Privacy and data handling (Product v1)

## Principles

- Local-first evidence and reports under `.dare-security/runs/`.
- Telemetry **disabled by default** and forbidden under confidential/offline.
- Automatic redaction of tokens, auth headers, cookies, private keys, passwords, connection strings, and env-like secrets before reports/diagnostics.
- Credential graph nodes use logical identities, never raw secret values.
- Classification metadata is rendered on HTML reports.

## Modes

| Mode | Telemetry | Network | Behavior |
|------|-----------|---------|----------|
| Standard (default) | off | restricted | Product assess still does not call remote APIs |
| Confidential | off | denied | Fail-closed egress; classification CONFIDENTIAL |
| Offline flag | off | denied | Same fail-closed egress |

## Retention

Config `privacy.retention_days` documents intended local retention (default 30). Operators own deletion of run directories.

## What is never collected

- Customer source code as telemetry
- Raw credentials
- Crash/analytics uploads
- Remote model/API dependency for product assess

See also [v1-contract.md](v1-contract.md) and [../responsible-disclosure.md](../responsible-disclosure.md).
