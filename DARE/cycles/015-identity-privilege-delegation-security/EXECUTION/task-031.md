# task-031 — Add validate identity-security CLI integration

**Status:** APPROVED FOR EXECUTION
**Dependencies:** task-020..task-022, task-029, task-030

## Objective
Expose the finished engine as `dare-agent-security validate identity-security`.

## Acceptance
Only approved local/replay flags exist; remote/OAuth/JWT/credential/PDP/AuthZEN/command flags are rejected; exit semantics are deterministic.