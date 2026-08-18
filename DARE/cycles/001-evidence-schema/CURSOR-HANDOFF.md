# Cursor Handoff — Cycle 001 Evidence Schema

> Status: **EXECUTE ONLY**
> Cycle: `001-evidence-schema`
> Approved: 2026-08-18

## Instruction

Execute this cycle exactly from the approved DARE artifacts. Do not redesign it.

Read in this order before implementation:

1. `APPROVAL.md`
2. `DESIGN.md`
3. `BLUEPRINT.md`
4. `TASKS.md`
5. `dare-dag.yaml`
6. the relevant `EXECUTION/task-NNN.md`

## Execution model

Follow dependency order from `dare-dag.yaml`.

For each task:

```text
read task spec
   -> implement only approved scope
   -> run task validation gates
   -> fix until green
   -> record completion evidence
   -> continue only when dependencies are satisfied
```

## Mandatory constraints

- Rust is the implementation language for the evidence kernel.
- Keep `dare-security-evidence` protocol-neutral.
- No MCP/AuthZEN/COAZ/customer-specific domain fields in the generic core.
- No raw credentials in evidence records or error messages.
- Unknown schema major versions fail closed.
- Contradictory verdicts must fail validation.
- `INCONCLUSIVE` and `ERROR` never become `PASS` implicitly.
- No network dependency is required to validate a canonical evidence record.
- No TODO/FIXME/stub/mock may remain in production code at task completion.
- Do not weaken tests or invariants to make gates pass.

## Required final gates

At minimum:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Also execute all schema, fixture, negative-security and redaction gates defined in the task specs.

## Stop conditions

Stop execution and return for DARE Review if:

- implementation conflicts with `DESIGN.md` or `BLUEPRINT.md`;
- a task requires protocol-specific assumptions in the generic evidence crate;
- a security invariant would need to be weakened;
- public/customer/proprietary boundaries become ambiguous;
- a required architectural decision is absent from the approved artifacts.

Do not resolve an architectural ambiguity by silently expanding scope.

## Completion output

When all tasks are complete, provide:

- task-by-task completion status;
- changed files summary;
- commands/gates executed and results;
- security invariant proof summary;
- any deviations (expected: none, otherwise explicit);
- final task-010 end-to-end proof result;
- commit/branch/PR information if applicable.

Cycle status remains **APPROVED FOR EXECUTION** until final human/DARE review marks it DONE.
