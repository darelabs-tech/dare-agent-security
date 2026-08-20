# Cycle 007 — MCP Security Benchmark & Corpus Methodology

**Status:** DESIGN READY FOR REVIEW  
**Cycle:** 007  
**Name:** MCP Security Benchmark & Corpus Methodology  
**Base branch:** `main`  
**Planning baseline:** Cycles 001–006 delivered on `main`  
**Proposed branch:** `agent/cycle-007-mcp-security-benchmark-corpus-methodology`  
**Approval:** PENDING — do not create `APPROVAL.md` before explicit human approval.

## Context

Delivered foundation:

```text
001 Evidence Kernel
002 Passive MCP Discovery
003 Authorization-to-Execution Integrity
004 CI Security Gate
005 Synthetic MCP Security Lab
006 Assessment Profiles & Coverage Engine
```

DARE Agent Security can now discover, plan, validate, produce deterministic evidence, measure coverage, run in CI, and self-test against synthetic ground truth.

Cycle 007 adds a new capability:

> **a reproducible measurement system for real MCP implementations.**

## Problem

A benchmark can produce misleading numbers if it does not freeze:

```text
which repositories were selected
which commit was assessed
which profile/version was used
which properties applied
which checks executed
which targets were excluded
how forks/duplicates were handled
how coverage affected denominators
how findings were human-validated
which engine/policies produced the result
```

Without those controls, statements such as:

```text
"X% of MCP servers are vulnerable"
```

are not reproducible.

## Goal

Create a benchmark pipeline:

```text
Corpus Definition
      ↓
Target Selection
      ↓
Pinned Revision
      ↓
Assessment Profile
      ↓
Applicability + Scope
      ↓
Assessment Plan
      ↓
Static / Local-Passive Validation
      ↓
Deterministic Evidence
      ↓
Coverage + Findings
      ↓
Human Validation
      ↓
Benchmark Record
      ↓
Aggregate Report
```

## Core principles

### Reproducibility before scale

A benchmark of 25 reproducible targets is more valuable than 500 targets assessed under changing rules.

### Immutable target revisions

Every target must record:

```text
repository
commit SHA
retrieved_at
license
```

A moving branch such as `main` is insufficient.

### Same profile, explicit applicability

Targets are compared under a declared profile and version.

Differences in capability are represented through Cycle 006 applicability/scope/execution semantics, not by silently changing the property set.

### Coverage belongs in the benchmark

Example:

```text
Target A
FAIL: 2
Assessment Coverage: 96%

Target B
FAIL: 0
Assessment Coverage: 41%
```

These are not equivalent security outcomes.

### Static/passive by default

For third-party public OSS, default to:

```text
public source analysis
+
local execution where safe
+
passive protocol inspection against local/synthetic instances
```

Do not actively test third-party production infrastructure without explicit authorization.

### No hidden denominator

Every published percentage must define:

```text
numerator
denominator
exclusions
coverage threshold
confidence threshold
```

### Responsible disclosure

The benchmark must not automatically publish:

- live secrets;
- credentials;
- unpatched critical exploit chains;
- production endpoints;
- unnecessary exploit detail.

## Benchmark object model

Introduce three explicit objects:

```text
Corpus Manifest
Benchmark Run
Benchmark Record
```

### Corpus Manifest

```yaml
schema_version: "1"

corpus:
  id: mcp-oss-2026-q3
  version: "1.0.0"

selection:
  source: public-github
  inclusion:
    - contains MCP server implementation
    - source publicly retrievable
    - license permits analysis
  exclusion:
    - generated mirrors
    - duplicate forks
    - docs-only repositories

targets:
  - id: target-0001
    repository: owner/repo
    commit: <sha>
    license: Apache-2.0
    discovered_at: <timestamp>
```

### Benchmark Run

```yaml
benchmark_run:
  id: run-2026-q3-001

  corpus:
    id: mcp-oss-2026-q3
    version: "1.0.0"
    digest: sha256:...

  engine:
    version: <version>
    commit: <sha>

  property_registry:
    version: <version>
    digest: sha256:...

  assessment_profile:
    id: mcp-security-baseline
    version: <version>
    digest: sha256:...

  policies:
    coverage:
      version: <version>
      digest: sha256:...
    severity:
      version: <version>
      digest: sha256:...
    confidence:
      version: <version>
      digest: sha256:...
```

### Benchmark Record

```yaml
benchmark_record:
  target:
    id: target-0001
    repository: owner/repo
    commit: <sha>

  assessment:
    plan_digest: sha256:...
    evidence_bundle_digest: sha256:...

  coverage:
    assessment_coverage: 0.92
    execution_coverage: 0.97
    not_applicable: 8
    out_of_scope: 0
    not_tested: 2
    blocked: 1
    error: 0

  findings:
    pass: 31
    fail: 4
    inconclusive: 1
    error: 0
```

## Corpus methodology

### Population definition

The benchmark must state what population it actually measures.

Example:

```text
public GitHub repositories containing MCP server implementations
```

Do not generalize that automatically to:

```text
all MCP servers
```

### Inclusion criteria

Baseline:

- public source;
- MCP server/server-capable implementation;
- retrievable pinned revision;
- license compatible with analysis;
- target identity can be frozen;
- implementation can be classified.

### Exclusion criteria

Baseline:

- clients only;
- docs-only repositories;
- dead links;
- mirrors without provenance;
- duplicate forks with no material difference;
- targets requiring unauthorized production access.

### Fork and duplicate policy

Classify lineage as:

```text
CANONICAL
MATERIAL_FORK
MIRROR
VENDOR_COPY
EXAMPLE
```

Only materially independent implementations count independently in headline prevalence by default.

### Sampling strategy

Recommended phases:

```text
Pilot       25–50 targets
Expanded    ~100 targets
Research    250+ targets
```

The pilot is a **method-validation corpus**, not an ecosystem census.

### Stratification

Useful dimensions:

- language;
- SDK;
- transport;
- authentication model;
- activity;
- organization vs individual maintainer;
- capability count;
- popularity metadata.

## Benchmark profile

Task 001 must reconcile the actual post-Cycle-006 profile model.

Prefer reusing:

```text
mcp-security-baseline
```

if it is suitable.

Only properties with reproducible applicability and stable evidence semantics should enter automated benchmark prevalence calculations.

Do not invent parallel verdict or coverage models.

## Coverage eligibility

A target should not automatically enter prevalence denominators.

Example policy:

```yaml
benchmark_policy:
  min_assessment_coverage_for_prevalence: 0.80
  max_error_ratio: 0.05
```

A low-coverage target remains visible in corpus statistics but may be excluded from security-prevalence denominators.

## Aggregate metrics

### Property Failure Rate

For property P:

```text
failure_rate(P)
=
eligible targets where verdict(P) == FAIL
/
eligible targets where P was
APPLICABLE + IN_SCOPE + completed
```

Never divide by the full corpus when the property is conditional.

### Coverage

Publish:

```text
median
p25
p75
minimum
maximum
```

for Assessment Coverage.

### Blind spots

Publish:

```text
ERROR ratio
BLOCKED ratio
NOT_TESTED ratio
OUT_OF_SCOPE ratio
NOT_APPLICABLE ratio
```

### Severity and confidence

Distinguish:

```text
finding count
```

from:

```text
affected target count
```

Primary prevalence claims should use an explicit confidence threshold.

## Human validation

Automation requires external validation.

### Positive sample

Human-review automated FAIL findings to estimate precision.

### Negative sample

Human-review PASS/no-finding cases to identify missed detections.

### Ambiguous sample

Review:

```text
INCONCLUSIVE
ERROR
NOT_TESTED
```

to identify automation gaps.

Record:

```text
sample method
sample size
reviewer
review date
decision
disagreement
resolution
```

If the sample is too small for statistical inference, report it descriptively.

## Relationship to Cycle 005

Cycle 005:

```text
known expected outcome
→ controlled ground truth
```

Cycle 007:

```text
unknown real-world outcome
→ observational evidence
```

Do not use the public corpus as the only regression oracle.

Do not treat lab success as ecosystem prevalence.

## Reproducibility

A run must freeze:

```text
corpus manifest/digest
target commit SHAs
engine commit
property registry version/digest
profile version/digest
policy versions/digests
assessment-plan digests
runner version
environment/container digest
```

## Longitudinal compatibility

Future studies must distinguish:

```text
target changed
engine changed
profile changed
property changed
policy changed
```

This enables later quarterly or MCP-release-based comparison.

## Responsible disclosure

### Publish freely

- aggregate statistics;
- methodology;
- non-actionable patterns;
- fixed/publicly disclosed findings;
- synthetic reproductions.

### Hold / coordinate

- unpatched high-impact vulnerabilities;
- live secrets;
- production exploit paths;
- zero-day-quality findings;
- exploit details that materially increase risk.

Targets may be anonymized while disclosure is pending.

## Safety boundary

Default Cycle 007 public OSS mode:

```text
STATIC
+
LOCAL_PASSIVE
```

Out of scope by default:

- third-party production exploitation;
- credential guessing;
- destructive/state-changing remote tests;
- exfiltration;
- denial of service;
- uncontrolled internet scanning.

Dynamic third-party testing requires explicit authorization and ROE.

## Expected implementation outputs

```text
schemas/
  corpus-manifest.schema.json
  benchmark-run.schema.json
  benchmark-record.schema.json

benchmark/
  profiles/
  policies/
  corpus/
  runner/
  reports/

docs/
  benchmark-methodology.md
  responsible-disclosure.md
  interpretation-guide.md
```

Exact repository paths must follow conventions discovered in Task 001.

## Optional publication

A later external report may be:

> **State of MCP Security 2026**

It is not required for Cycle 007 completion unless explicitly approved.

## Claims discipline

Good claim:

> "In our corpus of 42 eligible public OSS MCP implementations, 31% of targets for which property X was applicable, in scope, completed, and sufficiently covered produced a confirmed FAIL."

Avoid:

> "31% of MCP servers are vulnerable to X."

unless sampling justifies population inference.

## Scope

### In scope

- post-Cycle-006 reconciliation;
- corpus/run/record schemas;
- target pinning;
- dedup/lineage policy;
- sampling methodology;
- benchmark-profile compatibility;
- coverage eligibility;
- aggregation math;
- human validation;
- reproducibility;
- disclosure policy;
- safe benchmark runner;
- pilot corpus;
- CI regression tests;
- docs and final proof.

### Out of scope

- active third-party exploitation;
- internet-wide active scanning;
- SaaS benchmark dashboard;
- vendor leaderboard;
- definitive population claims from convenience samples;
- Agent Attack Graph implementation;
- continuous validation platform.

## Acceptance criteria

1. Post-Cycle-006 `main` reconciled.
2. Versioned Corpus Manifest schema exists.
3. Versioned Benchmark Run schema exists.
4. Versioned Benchmark Record schema exists.
5. Every target is pinned to an immutable revision.
6. Fork/duplicate handling is explicit and tested.
7. Inclusion/exclusion criteria are documented.
8. Sampling limitations are documented.
9. Benchmark profile/version is explicit.
10. Cycle 006 applicability/scope/execution contracts are reused.
11. Coverage eligibility threshold is explicit.
12. `ERROR`, `BLOCKED`, `NOT_TESTED`, `OUT_OF_SCOPE`, `NOT_APPLICABLE` remain visible.
13. Property prevalence uses property-specific denominators.
14. Human validation samples both positives and negatives.
15. Cycle 005 remains controlled ground truth.
16. Reproducibility manifest captures target/engine/profile/policy versions.
17. Runner emits deterministic machine-readable records.
18. Finding count and affected-target count are distinct.
19. Confidence threshold is explicit.
20. Responsible-disclosure policy exists.
21. Third-party dynamic testing is disabled by default.
22. Pilot corpus runs without unauthorized remote infrastructure.
23. Benchmark infrastructure has regression tests.
24. Final DARE proof maps every criterion to file/test/result.
25. `APPROVAL.md` remains absent until explicit approval.

## Exit gate

Human review must confirm:

- population definition;
- inclusion/exclusion;
- dedup policy;
- pilot size;
- profile;
- coverage threshold;
- human-validation sample;
- disclosure policy;
- publication claims policy;
- whether a public "State of MCP Security 2026" report is in scope.
