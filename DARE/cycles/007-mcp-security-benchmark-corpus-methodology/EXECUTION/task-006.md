# task-006 — Define sampling and corpus-selection methodology

**Cycle:** 007 — MCP Security Benchmark & Corpus Methodology  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective

Document population, inclusion/exclusion, stratification, pilot size and limits on representativeness claims.

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
