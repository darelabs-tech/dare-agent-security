# /dare-tasks

Use the DARE Method task-decomposition phase for the selected cycle.

## Required context

Read `DARE/AGENT-WORKFLOW.md`, then the selected cycle's approved `DESIGN.md` and approved `BLUEPRINT.md`.

## Generate cycle-local artifacts

Create or update only:

```text
DARE/cycles/<cycle>/TASKS.md
DARE/cycles/<cycle>/dare-dag.yaml
DARE/cycles/<cycle>/dag-graph.mmd
DARE/cycles/<cycle>/EXECUTION/task-*.md
```

## Rules

- Tasks must be atomic, independently testable and sufficiently detailed to avoid invented implementation.
- `depends_on` must represent real technical prerequisites, not artificial sequencing.
- Every task needs explicit validation gates and a Definition of Done.
- Apply the Anti-Stub contract from `DARE/AGENT-WORKFLOW.md`.
- Preserve Design and Blueprint security invariants.
- Do not mark tasks DONE during planning.
- After task artifacts are generated, stop for human approval before execution.
- For an already approved cycle, do not regenerate or split tasks without explicit human authorization.

$ARGUMENTS
