# Technical Report

`reports/technical.html` is the full-detail counterpart to the
[Executive Report](executive.md), written for the engineer who has to verify
or fix a finding.

## What it contains

- Every finding with its full [evidence](../concepts/evidence.md) record:
  expected vs. observed, request/policy/trace, verdict.
- Full per-property [coverage](../concepts/assessment-coverage.md) status,
  including `INCONCLUSIVE`/`BLOCKED` properties the executive report may
  summarize away.
- [Attack graph](../concepts/attack-graph.md) paths, when generated.
- Links to the underlying JSON artifacts for scripted follow-up.

## Known v1 scope

PDF export is out of scope for v1 — HTML is the primary technical report
format; use your browser's print-to-PDF if you need a static file to share.

## Regenerating it

```bash
dare-agent-security report --refresh
```
