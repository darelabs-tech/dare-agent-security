# Interpreting benchmark results (Cycle 007)

## Good claim

> In our corpus of N prevalence-eligible public OSS MCP fixtures, X% of targets for which property P was applicable, in scope, completed, and sufficiently covered produced a confirmed FAIL.

## Avoid

> X% of MCP servers are vulnerable to P.

unless the sampling design actually supports population inference (the pilot does not).

## Distinct counts

| Metric | Meaning |
|--------|---------|
| Finding count (FAIL) | Total FAIL verdicts across properties |
| Affected targets (FAIL) | Targets with ≥1 FAIL |

Low assessment coverage with 0 FAIL is **not** equivalent to high coverage with 0 FAIL.

## Blind spots

Publish ERROR / BLOCKED / NOT_TESTED / OUT_OF_SCOPE / NOT_APPLICABLE ratios. Do not hide them to improve a rate.
