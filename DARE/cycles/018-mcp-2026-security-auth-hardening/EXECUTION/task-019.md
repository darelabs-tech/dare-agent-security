# task-019 — Deterministic 14-invariant registry

**Status:** DONE - REVIEW PASS

Implement the approved closed set of 14 MCP auth invariants with total deterministic evaluation, independent violation retention and explicit required evidence. No LLM/heuristic final judgment.

## Evidence

`src/invariant.rs`. Fourteen evaluators, each a typed comparison. Order is harness-error, then violations, then coverage: checking coverage first would let a run with a real finding report INCONCLUSIVE because something unrelated was unobserved, hiding the finding behind a gap.
