# Redaction

Reports and diagnostics are automatically scrubbed before they're written or
displayed.

## What gets redacted

- Tokens and auth headers.
- Cookies.
- Private keys.
- Passwords.
- Connection strings.
- Env-like secret patterns.

## Credential graph nodes

When a [attack graph](../concepts/attack-graph.md) or evidence record needs
to reference a credential, it uses a **logical identity** (e.g. "service
account: billing-writer") rather than the raw secret value. Raw secrets
should never appear in any generated artifact.

## No credential flags, by design

There are no `--token`, `--password`, or `--credential` flags anywhere in
the CLI, and HTTP targets are HTTPS-only with credentials embedded in the
URL refused outright — see [`discover`](../commands/discover.md). This
removes an entire class of accidental-secret-in-shell-history risk rather
than relying on redaction alone as the only safeguard.

## If you find an unredacted secret in output

Treat it as a security bug in the tool itself and report it per
[Responsible Disclosure](https://github.com/darelabs-tech/dare-agent-security/blob/main/docs/responsible-disclosure.md) —
do not open a public issue.
