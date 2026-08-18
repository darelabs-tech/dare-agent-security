# /dare-refine

Analyze whether a DARE task should be split into smaller tasks.

Read `DARE/AGENT-WORKFLOW.md`, then the selected cycle Design, Blueprint, Tasks, DAG and target task spec.

Assess complexity, responsibility count, file surface, dependency boundaries and independent testability. Keep LOW and manageable MED tasks intact. Propose a split when a task is too broad, mixes strong responsibilities or cannot be reliably completed/reviewed as one unit.

Every proposed sub-task must be self-contained, testable, have minimal real dependencies and satisfy the Anti-Stub contract.

If the cycle already has `APPROVAL.md` with `APPROVED FOR EXECUTION`, refinement is proposal-only unless the human explicitly authorizes changing approved artifacts. Do not silently edit TASKS, DAG or EXECUTION specs. Stop the oversized task, present the proposed split and rationale, and return to human DARE Review.

If the cycle is not yet approved and the user authorizes refinement, update TASKS, DAG, graph and execution specs consistently.

$ARGUMENTS
