# /dare-execute

Execute one approved DARE task using the Ralph Loop.

Read `DARE/AGENT-WORKFLOW.md` first. Resolve the active cycle, then read the Product Design, cycle Approval (when present), cycle Design, Blueprint, Tasks, DAG and the selected `EXECUTION/<task-id>.md`.

For the current approved round, use `DARE/cycles/001-evidence-schema/` only if repository state still identifies it as active.

## Execution

1. Resolve `$ARGUMENTS` to a task id.
2. Verify all `depends_on` tasks are actually DONE.
3. Implement only the approved task specification; do not redesign the cycle.
4. Add real tests for required behavior and edge cases.
5. Execute every task-specific validation gate and repeat fixes until green.
6. For Rust, baseline gates are:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

7. Run additional schema, fixture, security, redaction and dependency gates required by the task.
8. Perform semantic/anti-stub review before marking DONE.
9. Preserve the approved task specification and append a clearly separated execution-result section rather than replacing it.
10. Report changed files, tests, validation results and the next dependency-ready task.

Never weaken tests/security invariants to make a gate pass. Never add raw credentials to evidence/errors. Stop and return for human DARE Review if implementation requires architecture changes, scope expansion, weakened security properties, ambiguous IP/public boundaries or an unapproved task split.

$ARGUMENTS
