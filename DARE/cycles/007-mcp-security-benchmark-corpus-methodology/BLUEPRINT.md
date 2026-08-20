# Cycle 007 — Blueprint

**Status:** ARCHITECTURE PROPOSED  
**Approval:** PENDING

## Dependency statement

Cycle 007 reuses Cycles 001–006.

It must not create parallel:

```text
evidence
verdict
coverage
property registry
assessment profile
```

## Pipeline

```text
Target Discovery
      ↓
Corpus Candidate
      ↓
Inclusion / Exclusion
      ↓
Dedup / Lineage
      ↓
Pinned Commit
      ↓
Corpus Manifest
      ↓
Benchmark Run
      ↓
Cycle 006 Assessment Plan
      ↓
Existing DARE Validation
      ↓
Cycle 001 Evidence
      ↓
Cycle 006 Coverage
      ↓
Benchmark Record
      ↓
Human Validation
      ↓
Aggregate Analysis
      ↓
Publication-safe Export
```

## Components

### Corpus Registry
Owns target IDs, repository identity, commit SHA, license, lineage, and stratification metadata.

### Benchmark Runner
Thin orchestration over existing DARE commands. It must not reimplement security logic.

### Benchmark Record
One normalized record per target/run.

### Aggregator
Owns eligibility, denominators, descriptive statistics, stratification, and confidence filtering.

### Human Validation Ledger
Appends human review metadata without mutating machine evidence.

### Disclosure Ledger
Tracks publication state, e.g.:

```text
PUBLIC
DISCLOSURE_PENDING
EMBARGOED
REDACTED
FIXED
```

Final vocabulary requires review.

## Stable target identity

Use internal target IDs independent of repository URL:

```text
mcp-target-000001
```

Always retain pinned commit SHA.

## Corpus digest

Reuse Cycle 006 digest/canonicalization if available.

Preferred pattern:

```text
normalized data model
↓
RFC 8785
↓
SHA-256
```

Do not invent another scheme if one already exists.

## Benchmark Run identity

Freeze:

```text
corpus digest
engine commit
profile digest
registry digest
coverage-policy digest
severity-policy digest
confidence-policy digest
runner version
environment/container digest
```

## Safety modes

Runner modes:

```text
STATIC
LOCAL_PASSIVE
AUTHORIZED_DYNAMIC
```

Public OSS pilot defaults to:

```text
STATIC + LOCAL_PASSIVE
```

## Eligibility engine

Conceptual rule:

```text
eligible_for_property_prevalence(record, property):
    property.applicability == APPLICABLE
    AND property.scope == IN_SCOPE
    AND property.execution == TESTED
    AND property.verdict != ERROR
    AND record.assessment_coverage >= threshold
```

Exact semantics must follow Cycle 006.

## Property prevalence

```text
eligible(P) =
targets where P was applicable, in scope,
completed, and benchmark-eligible

failed(P) =
eligible targets where verdict(P) == FAIL

failure_rate(P) =
failed(P) / eligible(P)
```

If denominator is too small:

```text
N/A
```

or descriptive only.

## Corpus lineage

Candidate:

```yaml
lineage:
  type: CANONICAL | MATERIAL_FORK | MIRROR | VENDOR_COPY | EXAMPLE
  parent_target_id: null
```

## Human validation

Three streams:

```text
FAIL sample
→ precision review

PASS/no-finding sample
→ missed-detection review

INCONCLUSIVE/ERROR/NOT_TESTED sample
→ automation-gap review
```

## Reproducible execution environment

Prefer containerized execution.

Record:

```text
container image digest
OS
architecture
language runtimes
lockfile digests
network mode
```

Default network should be restricted.

## Pilot corpus

Recommended:

```text
25–50 targets
```

Purpose:

```text
methodology validation
```

not population inference.

## Reporting

Machine:

```text
benchmark-run.json
benchmark-record-*.json
aggregate.json
human-validation.json
```

Human:

```text
methodology.md
corpus-summary.md
aggregate-findings.md
limitations.md
```

Publication-safe output is separate from internal evidence.

## Statistical discipline

Cycle 007 is primarily descriptive.

Use:

```text
count
proportion
median
p25
p75
range
```

Do not imply random sampling unless the sampling design is actually random.

## Security of the benchmark itself

Threats:

- malicious repository content;
- build-script execution;
- dependency poisoning;
- prompt injection in docs/source;
- symlink/path traversal;
- secrets in repositories;
- resource exhaustion;
- network exfiltration;
- malicious submodules.

Controls:

- sandbox;
- resource limits;
- restricted network;
- no arbitrary build/install by default;
- safe traversal;
- redaction;
- pinned revisions;
- isolated workspaces.

## CI

CI validates benchmark infrastructure with small fixtures.

It should test:

```text
schemas
canonicalization
eligibility math
dedup
aggregate denominators
runner safety defaults
human-validation ledger
publication export
```

Do not run the entire public corpus on every PR.
