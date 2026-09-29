# task-013 — Implement evaluators B-1 (tool authorization) and B-2 (approval)

**Status:** DONE  
**Complexity:** MED

## `src/evaluate/mod.rs`

The shared frame for every evaluator:
- **`Rule`:** 9 rules, B-4 being split into B-4R and B-4M (R-5). Each rule knows its
  `property_id`, its `code` and whether it `needs_policy`.
- **`TraceVerdict`:** FAIL, INCONCLUSIVE, PASS or NOT_EXERCISED.
- **`Violation{reason, span_ids, keys, fingerprints}`:** keys and fingerprints only,
  never a value.
- **`TraceOutcome`:** one rule's result for one trace.
- **`Context`:** the view, mapping, policy and stop flag, plus acting-agent helpers (the
  nearest `invoke_agent` ancestor, or the span itself).
- **`outcome()`:** a seen violation is FAIL; else any gap is INCONCLUSIVE; else an
  observation is PASS; else NOT_EXERCISED.
- **`testkit`:** a small trace builder used by the evaluator tests.

## Evaluators

- **B-1 (`tool_auth.rs`).** A tool span is `execute_tool`, or MCP `tools/call`.
  - Unknown acting agent → `unknown_agent`.
  - Tool not in `allowed_tools` → `tool_not_allowed`.
  - Missing tool or agent name → gap.
- **B-2 (`approval.rs`).** A destructive tool call needs an event named by the policy,
  whose `tool_key` equals the tool and whose time is ≤ the call start.
  - Otherwise → `destructive_without_approval`.
  - Events dropped anywhere in the trace → `DroppedEvents` gap instead of FAIL (R-5).
  - No approval configured → gap.

## Tests

- B-1: allowed passes; disallowed fails and does not echo the tool name; unknown agent;
  MCP `tools/call`; no-agent, dropped attributes and orphans are never PASS; a violation
  on an incomplete trace is still FAIL; no tools → NOT_EXERCISED.
- B-2: approval before the call passes. Each of these fails: no approval, a late
  approval, another tool's approval, the wrong event name. Dropped events and no approval
  configuration are INCONCLUSIVE. Non-destructive calls → NOT_EXERCISED.

Ralph Loop: clippy `-D warnings` (1.98.1), fmt, tests green.
