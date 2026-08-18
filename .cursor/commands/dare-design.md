# /dare-design

Use the DARE Method Design phase for this repository.

## Required context

Read `DARE/AGENT-WORKFLOW.md` first.

This repository has two design levels:

- `DARE/DESIGN.md` = Product Design. Do not modify unless the user explicitly asks for a product-level change.
- `DARE/cycles/<cycle>/DESIGN.md` = Cycle Design. This is the default target for an implementation round.

## Workflow

1. Resolve the target cycle using `DARE/AGENT-WORKFLOW.md` or the user's explicit cycle.
2. Read `DARE/DESIGN.md` as the global product constraint.
3. Inspect current repository state and relevant issue/requirements.
4. Create or update only the selected cycle's `DESIGN.md`.
5. Define objective, problem, use cases, required information, security properties, versioning where relevant, non-goals, technical direction and measurable acceptance criteria.
6. Keep customer/private/proprietary information out of public artifacts.
7. Stop after Design and request human approval before Blueprint.

## Rule

Never advance directly from Design to implementation. Human approval is mandatory before `/dare-blueprint`.

$ARGUMENTS
