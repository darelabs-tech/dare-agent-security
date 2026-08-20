# MCP Security Benchmark Methodology (Cycle 007)

**Status:** Pre-release. Pilot validates methodology, not ecosystem prevalence.

## What it measures

A reproducible measurement system for MCP implementations under a frozen profile, registry, engine, and policy set — with coverage-aware denominators.

## Population (pilot)

```text
synthetic methodology fixtures representing public OSS MCP server shapes
```

Do **not** generalize pilot results to “all MCP servers.”

## Schemas

| Artifact | Path |
|----------|------|
| Corpus Manifest | `schemas/benchmark/v1/corpus-manifest.schema.json` |
| Benchmark Run | `schemas/benchmark/v1/benchmark-run.schema.json` |
| Benchmark Record | `schemas/benchmark/v1/benchmark-record.schema.json` |
| Pilot corpus | `benchmark/corpus/pilot-methodology-v1/` |
| Policy | `benchmark/policies/benchmark-policy.json` |

## Inclusion / exclusion

Inclusion: MCP server-capable shape, pinned revision, analyzable license, freezable identity.  
Exclusion: docs-only, clients-only, mirrors without provenance, unauthorized production access.

## Dedup / lineage

```text
CANONICAL | MATERIAL_FORK → may enter headline prevalence
MIRROR | VENDOR_COPY | EXAMPLE → corpus-visible, excluded from headline prevalence
```

## Sampling limitations

Pilot size is 25–50 targets for **method validation**. Convenience/fixture sampling does not justify random-population inference.

## Coverage eligibility

Default policy:

```text
min_assessment_coverage_for_prevalence = 0.80
max_error_ratio = 0.05
min_confidence_for_prevalence = 0.70
min_eligible_targets_for_rate = 5
```

Property prevalence uses property-specific eligible denominators (Cycle 006 APPLICABLE + completed + confidence), never the full corpus for conditional properties.

## Runner safety

Defaults: `STATIC` / `LOCAL_PASSIVE`, restricted network.  
`AUTHORIZED_DYNAMIC` requires policy allow + explicit ROE flag.

## CLI

```bash
dare-agent-security validate benchmark \
  --corpus benchmark/corpus/pilot-methodology-v1/corpus-manifest.json \
  --output-dir .dare-agent-security/benchmark \
  --mode local-passive
```

## Digests

SHA-256 over recursively key-sorted JSON (JCS-style). Reuses Cycle 006 profile digests where applicable.
