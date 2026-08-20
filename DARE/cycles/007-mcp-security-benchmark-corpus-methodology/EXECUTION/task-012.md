# task-012 — Build pilot corpus

**Cycle:** 007 — MCP Security Benchmark & Corpus Methodology  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective

Assemble a 25–50 target public OSS method-validation corpus, each target pinned to an immutable commit.

## Safety boundary

For public third-party targets:

```text
public source
+
static analysis
+
local/synthetic passive execution
```

Active state-changing testing against third-party infrastructure requires explicit authorization and Rules of Engagement.

## DARE execution rule

Do not mark this task complete from code appearance alone.

Capture deterministic evidence for acceptance.

If repository reality contradicts `DESIGN.md`, `BLUEPRINT.md`, or actual post-Cycle-006 contracts, return to Review before changing benchmark semantics.
