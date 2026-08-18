# /dare-execute

Execute one approved DARE task using the Ralph Loop.

## Required context

Read `DARE/AGENT-WORKFLOW.md` first. Resolve the active cycle, then read in order:

1. `DARE/DESIGN.md`
2. cycle `APPROVAL.md` when present
3. cycle `DESIGN.md`
4. cycle `BLUEPRINT.md`
5. cycle `TASKS.md`
6. cycle `dare-dag.yaml`
7. cycle `EXECUTION/<task-id>.md`

For the current approved round, use `DARE/cycles/001-evidence-schema/` if repository state still shows it as active.

## Execution

1. Resolve `$ARGUMENTS` to a task id.
2. Verify every `depends_on` task is actually DONE. Do not use `--force` to bypass failed/incomplete dependencies.
3. Implement only the approved task spec. Do not redesign the cycle.
4. Add real tests for required behavior and edge cases.
5. Run every validation gate in the task spec.
6. Run the Ralph Loop: read failures, fix implementation, rerun until all required gates are green.
7. For Rust, baseline gates are:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

8. Run additional schema, fixture, redaction, security and dependency gates required by the task.
9. Perform anti-stub/semantic review before marking DONE.
10. Update the task status/evidence only after gates pass. Preserve the approved task spec; append a clearly separated execution-result section rather than replacing the specification.
11. Report changed files, tests, gate results and the next dependency-ready task.

## Invariants

- No TODO/FIXME/stub required behavior in production code at completion.
- Never weaken tests, lint, security invariants or validation to make a gate pass.
- Never expose raw credentials in evidence/errors.
- Do not introduce MCP/AuthZEN/COAZ/customer-specific concepts into the generic evidence core unless an approved artifact requires them.
- Unknown schema major versions must fail closed when this property is in scope.
- Contradictory deterministic verdicts must fail validation when this property is in scope.

## Stop conditions

Stop and return for human DARE Review if implementation requires architecture/design changes, scope expansion, weakened security properties, ambiguous IP/public boundaries or an unapproved task split.

$ARGUMENTS
