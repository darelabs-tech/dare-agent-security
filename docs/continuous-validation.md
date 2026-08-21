# Continuous Agent Security Validation

Cycle 010 compares an explicit trusted baseline with a candidate immutable security-state snapshot. It is offline, deterministic, and coordinates the evidence, coverage, property, attack-graph/path, and adversarial contracts delivered by Cycles 001–009; it does not replace those engines.

## Quick start

```bash
cargo run -p dare-agent-security -- validate continuous \
  --fixture fixtures/continuous/unrelated-change.json \
  --mode plan-only \
  --output-dir .dare-agent-security/continuous
```

For real snapshots, name both sides explicitly:

```bash
cargo run -p dare-agent-security -- validate continuous \
  --baseline trusted-main-snapshot.json \
  --candidate current-snapshot.json \
  --policy continuous-policy.json \
  --mode revalidate \
  --output-dir .dare-agent-security/continuous
```

The command writes `security-changeset.json`, `revalidation-plan.json`, and `continuous-report.json`. It never selects an arbitrary “latest” baseline.

## Snapshot and drift semantics

Snapshots are immutable and digested as key-sorted JSON with SHA-256. They bind target revision, inventory, registry, profile, assessment plan, evidence, coverage, graph, validation results, policies, and semantic facts.

Drift is `IMPROVED`, `REGRESSED`, `UNCHANGED`, or `UNKNOWN`. Reports include property verdict transitions, coverage deltas, risky path changes, and controlled-validation transitions. Missing proof never becomes `PASS` or `UNCHANGED`.

## Reuse and cache

`REUSE` requires:

- the exact trusted baseline digest;
- original evidence references;
- the same complete dependency key set;
- known and equal values for every security-relevant dependency.

An omitted or unknown dependency denies reuse. The cache only returns an existing evidence-backed result for an exact deterministic key; it cannot synthesize a verdict.

## Impact and full fallback

The built-in dependency map uses IDs from the Cycle 006 registry. Known isolated changes select affected properties, Cycle 008 paths, and Cycle 009 vectors. Missing mappings or incomplete facts force full-surface `REVALIDATE`; there is no silent partial reuse.

## Dynamic safety boundary

Continuous validation can plan offline modes, but `AUTHORIZED_DYNAMIC` is never auto-approved. Cycle 009 Rules of Engagement, budget, preconditions, and kill-switch checks remain authoritative. A continuous policy that disables unknown fallback or auto-enables dynamic mode is refused.

## CI and remediation

The `continuous-validation` CI job runs the deterministic fixture matrix and a local CLI plan. A fix can be represented as a baseline `FAIL` followed by candidate `PASS`; the same affected property is revalidated and reported as `IMPROVED`.

## History

`SnapshotHistory` writes digest-named snapshots and transition records with create-new semantics. Existing history entries are never overwritten.

## Performance baseline

`fixtures_matrix::incremental_plan_is_smaller_than_full_fallback` verifies the MVP optimization invariant: a mapped isolated change selects fewer revalidations than unknown-impact full fallback. Correctness and fail-closed behavior take precedence over timing.

## CORE FEATURE FREEZE

After Cycle 010 acceptance, the core security feature set is frozen. Cycle 011 is limited to productization and v1.0 release readiness unless a security defect requires correction.
