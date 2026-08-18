# /dare-refine

Analyze whether a DARE task should be split into smaller tasks.

## Required context

Read `DARE/AGENT-WORKFLOW.md`, then the selected cycle's Design, Blueprint, Tasks, DAG and target task spec.

## Workflow

1. Resolve `$ARGUMENTS` to a task id.
2. Assess complexity, responsibility count, file surface, dependency boundaries and independent testability.
3. Keep LOW and manageable MED tasks intact.
4. Propose a split when a task is too broad, mixes strong responsibilities, or cannot be reliably completed/reviewed as one unit.
5. Each proposed sub-task must be self-contained, testable, have minimal real dependencies and satisfy the Anti-Stub contract.

## Approval rule

If the cycle already has `APPROVAL.md` with `APPROVED FOR EXECUTION`, refinement is **proposal-only** unless the human explicitly authorizes changing the approved artifacts.

For an approved cycle:

- do not silently edit `TASKS.md`, `dare-dag.yaml` or `EXECUTION/`;
- stop execution of the oversized task;
- present the proposed split and rationale;
- return to human DARE Review for approval.

If the cycle is not yet approved and the user authorizes refinement, update TASKS, DAG, graph and individual execution specs consistently.

$ARGUMENTS
