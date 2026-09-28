# task-010 — Add the seven `schemas/remote-validation/v1` JSON schemas

**Status:** IN PROGRESS: 4 of 7 schemas added

## Done

- `authorization.schema.json`
- `plan.schema.json`
- `conversation-request.schema.json`
- `conversation-response.schema.json`

These four match the Rust models field for field (see the admission tests in
task-011). `PRODUCTION` and the non-synthetic data classes are listed in the enums, so
that verification refuses them by name (rules 3 and 9) rather than as a generic schema
error.

## Remaining

`capture`, `audit` and `result` are written with their modules (tasks 019, 020 and 033),
so each schema is checked against the struct it describes when it is written.
