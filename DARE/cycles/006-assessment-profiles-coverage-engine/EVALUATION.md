# Cycle 006 Capability Evaluation — Revised Baseline

## Decision

Cycle 006 remains a valid capability to plan from the post-Cycle-004 `main`, but it must be **independent of Cycle 005**.

## What changed from the previous draft

Previous draft assumed:

```text
Cycle 005 merged
```

This revised draft assumes:

```text
main = Cycles 001–004
Cycle 005 = unmerged / external to baseline
```

Therefore:

- Cycle 005 is removed from required dependencies.
- Cycle 005 scenario mapping is no longer a mandatory acceptance criterion.
- Cycle 006 gains local deterministic coverage fixtures.
- Cycle 005 integration becomes a conditional task.
- Core property IDs derive from delivered Cycle 001–004 capabilities only.

## Why Cycle 006 can remain independently valuable

Coverage is a separate capability from vulnerability-fixture validation.

Cycle 006 asks:

> What should this assessment test, what applied, what ran, and what did not?

That can be implemented using:

```text
existing discovery inventory
existing authorization-integrity outputs
existing evidence
existing CI gate
```

without the synthetic vulnerability corpus.

## Execution-order recommendation

Planning may proceed now.

Implementation should still follow the project's normal rule:

> Cycles are sequential by default and parallel only when independence is demonstrated.

If Cycle 005 is actively being finalized, the safest operational sequence remains:

```text
merge Cycle 005
then start Cycle 006 implementation
```

But Cycle 006 architecture no longer has a hard code dependency on it.
