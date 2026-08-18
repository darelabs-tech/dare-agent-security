# /dare-blueprint

Use the DARE Method Architect phase for the selected cycle.

## Required context

Read `DARE/AGENT-WORKFLOW.md`, then the selected cycle's approved `DESIGN.md`, and read `DARE/DESIGN.md` as the global product constraint.

## Workflow

1. Resolve the target cycle.
2. Confirm the cycle Design is human-approved.
3. Generate or update only `DARE/cycles/<cycle>/BLUEPRINT.md`.
4. Define concrete architecture, boundaries, typed contracts, repository layout, dependency direction, security invariants, validation strategy, testing strategy and implementation constraints.
5. Apply the Anti-Stub principle: enough detail must exist for an implementation agent to work without inventing missing behavior.
6. Do not generate TASKS, DAG or EXECUTION specs in this command.
7. Stop and request human approval of the Blueprint.

## Rules

- Never overwrite `DARE/DESIGN.md`.
- Never silently change an approved Cycle Design.
- If architecture requires a semantic Design change, return to Design review.
- Keep the OSS/proprietary/customer boundaries defined by the Product Design.

$ARGUMENTS
