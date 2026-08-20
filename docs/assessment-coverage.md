# Assessment profiles and coverage engine (Cycle 006)

**Status:** Pre-release. Coverage answers “what should have been tested?”, not “is the target secure?”.

## What it does

```text
Facts + Profile + Registry
        → Applicability Engine
        → Assessment Plan
        → existing analyzers (discover / coaz-integrity / lab)
        → Cycle 001 evidence ids
        → Coverage report
        → optional CI thresholds
```

The coverage crate (`dare-coverage`) does **not** replace Cycles 001–005 engines.

## Artifacts

| Artifact | Path |
|----------|------|
| Property schema | `schemas/coverage/v1/property.schema.json` |
| Registry | `schemas/coverage/v1/registry.json` |
| Profile schema | `schemas/coverage/v1/profile.schema.json` |
| Builtin profile | `profiles/mcp-security-baseline.json` |
| Report schema | `schemas/coverage/v1/coverage-report.schema.json` |
| Local fixtures | `fixtures/coverage/` |
| Cycle 005 map | `integrations/cycle-005/scenario-property-map.json` |

## CoverageStatus vs Verdict

| CoverageStatus | May have Cycle 001 verdict? |
|----------------|-----------------------------|
| APPLICABLE | yes (required at finalization) |
| NOT_APPLICABLE | no |
| NOT_TESTED | no |
| OUT_OF_SCOPE | no |
| BLOCKED | no |

`APPLICABLE` without a verdict finalizes to `NOT_TESTED`. It cannot silently become `PASS`.

ROE `BLOCKED` is never relabeled `NOT_APPLICABLE`.

## Denominator

```text
eligible = properties with a verdict + NOT_TESTED + BLOCKED
tested   = properties with a Cycle 001 verdict
coverage = tested / eligible   (1.0 if eligible is 0)

NOT_APPLICABLE and OUT_OF_SCOPE are excluded.
required_coverage uses the same formula on REQUIRED properties only.
```

## CLI

```bash
dare-agent-security validate coverage \
  --profile mcp-security-baseline \
  --facts fixtures/coverage/fixture-a-tools-static-roe.json \
  --output-dir .dare-agent-security \
  --min-required-coverage 0.8 \
  --fail-on-required-blocked
```

There is no top-level `coverage` command. Profiles are JSON data (no scripts).

## CI

Optional Action inputs: `profile`, `coverage-facts`, `min-required-coverage`, `fail-on-required-blocked`.

`ci-result.json` is unchanged (closed schema). Coverage is a sibling `coverage-report.json`.

## Cycle 005 adapter

If the lab corpus is present, `integrations/cycle-005/scenario-property-map.json` maps MCP-LAB-001..006 to registry ids. MCP-LAB-007..010 remain unmapped (lab-only / future) and do not change core coverage math.

## Limitations

- Does not claim production or Marketplace coverage completeness.
- Applicability uses a closed predicate enum, not a general policy language.
- Facts must be supplied; the coverage command does not scan the network.
