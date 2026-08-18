# /dare-tasks

Use the DARE Method task-decomposition phase for the selected cycle.

Read `DARE/AGENT-WORKFLOW.md`, then the selected cycle's approved `DESIGN.md` and `BLUEPRINT.md`.

Generate or update only cycle-local artifacts:

```text
DARE/cycles/<cycle>/TASKS.md
DARE/cycles/<cycle>/dare-dag.yaml
DARE/cycles/<cycle>/dag-graph.mmd
DARE/cycles/<cycle>/EXECUTION/task-*.md
```

Tasks must be atomic, independently testable and detailed enough to avoid invented behavior. Dependencies must represent real technical prerequisites. Every task requires explicit validation gates and a Definition of Done. Apply the Anti-Stub contract from `DARE/AGENT-WORKFLOW.md`.

Do not mark tasks DONE during planning. Stop for human approval before execution. If the cycle is already approved for execution, do not regenerate or split tasks without explicit human authorization.

$ARGUMENTS
