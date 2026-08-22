# Telemetry

**Telemetry is disabled by default**, and forbidden entirely under
[Confidential Mode](confidential-mode.md) or [Offline Mode](offline-mode.md).

## What that means concretely

- No usage analytics are sent anywhere out of the box.
- No crash reports are uploaded.
- No customer source code is ever transmitted as telemetry.
- Running `--confidential`/`--offline` makes this a hard, fail-closed
  guarantee rather than a default you could accidentally change.

## Config equivalent

`privacy.telemetry: false` in your project config is the default written by
`init` — see [Configuration](../reference/configuration.md). There is
currently no supported way to opt telemetry *on*; this reflects the
project's evidence-first, local-first design rather than a missing feature.

## Verifying it yourself

Run an assessment with network access blocked at the OS/firewall level and
confirm it still completes normally — that's the acceptance-level way to
verify the "no telemetry, no cloud upload" claim rather than trusting the
documentation alone.
