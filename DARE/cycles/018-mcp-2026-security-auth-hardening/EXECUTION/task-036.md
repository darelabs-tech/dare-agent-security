# task-036 — Local-synthetic adapter

**Status:** DONE - REVIEW PASS

Implement local-synthetic execution under Cycle 009 safety controls. Only synthetic auth artifacts and zero-egress, zero-state-change behavior are allowed.

## Evidence

`src/local_synthetic.rs`. Cycle 009 `ExecutionBudget` with zero state changes and zero egress. A run pointed at a scenario other than the one it was approved for trips the kill switch.
