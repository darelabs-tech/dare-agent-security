# /dare-review

Review an implemented task against its approved DARE specification.

Read `DARE/AGENT-WORKFLOW.md`, resolve the active cycle, then read the cycle Approval, Design, Blueprint, Tasks, DAG and `EXECUTION/<task-id>.md`.

Inspect the actual production code and tests. Audit criterion-by-criterion against the approved task spec: objective, required files/contracts, implementation requirements, edge cases, meaningful tests, security properties and validation gates.

Apply Anti-Stub review: no required TODO/FIXME/XXX/HACK, no empty required implementation, no `todo!()`/`unimplemented!()` or equivalent, no production mock/fake substituting missing behavior, and no meaningless tests.

Verify no Design/Blueprint invariant was weakened. If the DARE CLI review command is available, run it and combine static results with this semantic review; never fabricate unavailable CLI results.

Emit explicit PASS or FAIL with concrete evidence. A task may be marked DONE only when the semantic review passes and all required gates are green.

For Cycle 001, verify where applicable: protocol-neutral evidence core, secret-safe serialization/errors, fail-closed schema major handling, deterministic verdict consistency, redaction semantics and offline canonical evidence validation.

$ARGUMENTS
