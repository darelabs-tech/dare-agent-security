# task-019 — Add hostile parser/schema/trace fixtures and executable-field refusal

**Status:** APPROVED FOR EXECUTION

## Objective
Attack the validator's own input boundaries with malformed/untrusted data.

## Required hostile cases
Unknown fields/enums/versions, duplicate IDs, `shell`/`script`/`eval`/`callback`, path traversal, expected-verdict smuggling, digest substitution, hostile Unicode, oversized metadata/output, credential-shaped content and malicious log strings.

## Acceptance
All unsafe/malformed cases fail closed before execution.
