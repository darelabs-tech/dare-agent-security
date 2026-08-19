# task-006 — Implement Deterministic PDP and Bound Decision Model

> Status: **READY FOR REVIEW**
> Depends on: task-004, task-005

## Objective

Provide a local deterministic authorization decision source whose permit is explicitly associated with the binding evaluated.

## Requirements

- no network communication;
- fixture policy only;
- deterministic permit/deny;
- decision contains a stable fixture/run decision id and the authorization binding it evaluated;
- no token semantics beyond sanitized synthetic trusted context;
- original and mutated requests can intentionally produce different decisions.

## Minimum policy behavior

```text
rental.quote daily_rate <= 1000  -> PERMIT
rental.quote daily_rate > 1000   -> DENY
rental.quote_internal            -> DENY for standard synthetic subject
```

## Tests

- same projection -> same decision;
- changed mapped projection can change decision;
- decision records binding A;
- no accidental reuse of decision object for binding B in secure reference path.

## DONE when

Vectors can prove that an old permit was authorized for A and was or was not incorrectly used for B.
