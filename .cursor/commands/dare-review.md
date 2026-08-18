# /dare-review

Review an implemented task against its approved DARE specification.

## Required context

Read `DARE/AGENT-WORKFLOW.md`, resolve the active cycle, then read the cycle `APPROVAL.md`, `DESIGN.md`, `BLUEPRINT.md`, `TASKS.md`, `dare-dag.yaml`, and `EXECUTION/<task-id>.md`.

## Review procedure

1. Resolve `$ARGUMENTS` to a task id.
2. Inspect the actual changed production code and tests. Do not infer implementation from summaries.
3. Audit criterion-by-criterion against the approved task spec:
   - objective and observable outcome;
   - required files/contracts;
   - implementation requirements;
   - edge cases;
   - tests and meaningful assertions;
   - security properties;
   - validation gates.
4. Apply Anti-Stub review:
   - no required TODO/FIXME/XXX/HACK;
   - no empty required implementation;
   - no `todo!()`/`unimplemented!()` or equivalent;
   - no production mocks/fakes substituting missing behavior;
   - no meaningless tests.
5. Verify no approved Design/Blueprint invariant was weakened.
6. If DARE CLI review is available, run the static review and combine it with this semantic review. Do not fabricate CLI output when unavailable.
7. Emit an explicit PASS or FAIL with concrete evidence and unresolved criteria.
8. A task may be marked DONE only on PASS with all required gates green.

## Current security emphasis

For Cycle 001 verify, where applicable:

- protocol-neutral evidence core;
- secret-safe serialization/errors;
- fail-closed schema major handling;
- deterministic verdict consistency;
- redaction metadata semantics;
- no network dependency for canonical evidence validation.

$ARGUMENTS
