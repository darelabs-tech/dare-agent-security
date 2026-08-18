# /dare-blueprint

Use the DARE Method Architect phase for the selected cycle.

Read `DARE/AGENT-WORKFLOW.md`, the selected cycle's human-approved `DESIGN.md`, and `DARE/DESIGN.md` as the global product constraint.

Generate or update only `DARE/cycles/<cycle>/BLUEPRINT.md`. Define concrete architecture, typed contracts, repository layout, dependency direction, security invariants, validation/testing strategy and implementation constraints. Apply the Anti-Stub principle: provide enough detail that a later implementation agent does not need to invent missing behavior.

Do not generate TASKS, DAG or EXECUTION specs during this command. If architecture requires a semantic Design change, return to Design review. Stop and require human Blueprint approval before task decomposition.

$ARGUMENTS
