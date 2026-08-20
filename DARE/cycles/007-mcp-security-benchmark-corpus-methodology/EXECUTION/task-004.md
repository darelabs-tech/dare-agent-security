# task-004 — Define Benchmark Record schema

**Cycle:** 007 — MCP Security Benchmark & Corpus Methodology  
**Status:** READY FOR EXECUTION AFTER APPROVAL

## Objective

Create normalized one-target-per-run output reusing Cycle 001 evidence and Cycle 006 coverage/property types.

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
