# DARE Agent Workflow — dare-agent-security

This file defines how AI coding agents must apply the DARE Method inside this repository.

## Artifact hierarchy

There are two design levels:

```text
DARE/DESIGN.md
  -> Product Design: durable product vision, boundaries and strategic constraints

DARE/cycles/<cycle>/DESIGN.md
  -> Cycle Design: scope and acceptance criteria for one implementation round
```

For cycle implementation, the cycle-local artifacts are canonical, subject to the global Product Design.

## Cycle artifact order

For any cycle, read and respect artifacts in this order:

```text
DARE/DESIGN.md
DARE/cycles/<cycle>/APPROVAL.md       # when present
DARE/cycles/<cycle>/DESIGN.md
DARE/cycles/<cycle>/BLUEPRINT.md
DARE/cycles/<cycle>/TASKS.md
DARE/cycles/<cycle>/dare-dag.yaml
DARE/cycles/<cycle>/EXECUTION/task-NNN.md
```

`APPROVAL.md` freezes the approved planning snapshot for execution. Do not redesign approved artifacts during Execute.

## Selecting a cycle

1. If the user supplies a cycle path/name, use it.
2. Otherwise prefer the newest cycle under `DARE/cycles/` whose `APPROVAL.md` says `APPROVED FOR EXECUTION` and that still has incomplete tasks.
3. If more than one cycle is plausibly active, stop before writing code and ask which cycle is intended.

## DARE phases

### Design

Create or update only the selected cycle's `DESIGN.md` unless the user explicitly asks to alter the Product Design.

Never silently overwrite `DARE/DESIGN.md`.

### Architect / Blueprint

Read the approved cycle Design and create/update only the cycle `BLUEPRINT.md`.
Do not generate tasks until the Blueprint is human-approved.

### Tasks

After Blueprint approval, generate or update:

```text
TASKS.md
dare-dag.yaml
dag-graph.mmd
EXECUTION/task-*.md
```

Each task spec must be self-contained, testable and anti-stub.

### Review

Review the implementation against the approved task spec, cycle Blueprint, cycle Design and Product Design.
Require concrete evidence from code/tests/gates. Never infer that a criterion passed without inspecting it.

### Execute

Execute only tasks whose dependencies are satisfied.
For every task:

```text
read approved artifacts
-> read task spec
-> implement only approved scope
-> run validation gates
-> fix until green
-> run semantic/anti-stub review
-> update task status/evidence
-> continue only when dependencies are satisfied
```

Do not replace `EXECUTION/task-NNN.md` with a completion report. Preserve the approved spec and append/update a clearly separated execution-result section.

## Ralph Loop

A task is not DONE until its gates are green. For Rust tasks, the baseline is:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Run additional task-specific schema, fixture, security, redaction and dependency gates when defined.

Never weaken a test, invariant or lint rule merely to make a gate pass.

## Anti-stub contract

Production code at task completion must not contain implementation placeholders such as:

- TODO/FIXME/XXX/HACK for required behavior;
- empty public functions;
- `todo!()`, `unimplemented!()`, `NotImplementedError` or equivalent;
- mock/fake production implementations standing in for required behavior;
- meaningless tests whose assertions cannot fail for the intended behavior.

Mocks are acceptable in tests when they are not used to conceal missing production behavior.

## Security and repository boundaries

For DARE Agent Security specifically:

- never add customer source, private endpoints, credentials, findings or confidential architecture to the public repository;
- never copy proprietary NEXORA or DARE Runtime code into the Apache-2.0 repository without an explicit licensing/IP decision;
- active/adversarial functionality must remain authorized, scoped and safe-by-default;
- protocol-specific concepts must not leak into a generic core unless the approved cycle explicitly requires them;
- security errors/evidence must not echo raw secrets.

## Stop conditions

Stop implementation and return to human DARE Review when:

- code would conflict with an approved Design or Blueprint;
- an architectural decision is missing;
- security invariants would need to be weakened;
- scope must expand beyond the approved cycle;
- public/proprietary/customer boundaries become ambiguous;
- a task dependency is not actually complete.

Do not solve an architectural ambiguity by silently inventing a new design.

## Current execution round

At the time this workflow was installed, the approved execution round is:

```text
DARE/cycles/006-assessment-profiles-coverage-engine/
```

Always verify repository state before assuming this remains the active cycle.
