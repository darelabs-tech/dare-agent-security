# task-011 — Add Secure/Vulnerable E2E Proof and Negative Security Tests

> Status: **DONE**
> Depends on: task-010

## Objective

Make the central security property impossible to satisfy by documentation alone: prove it from captured execution traces.

## Critical vulnerable proof

For vectors 002–005 where the initial fixture permits:

```text
initial_decision = PERMIT
initial_binding != final_binding
sink.forwarded = true
binding_used_by_sink = initial_binding
observed = FORWARDED_WITH_STALE_PERMIT
verdict = FAIL
```

## Critical secure proof

For the same vectors:

```text
initial_binding != final_binding
old permit is not reused
observed in {
  REFUSED_AFTER_BINDING_CHANGE,
  DENIED_AFTER_REEVALUATION,
  FORWARDED_AFTER_REEVALUATION
}
verdict = PASS
```

If forwarded after re-evaluation, the sink must reference the new decision/binding.

## Control proof

Vectors 006–007 must show semantic binding equality.

## Negative security tests

- canary token/header/API-key strings absent from stdout/stderr/result/evidence;
- vulnerable mode refuses non-synthetic targets;
- malformed vector fails closed;
- projector error cannot reach sink;
- PDP error cannot reach sink;
- binding mismatch cannot reach sink in secure refuse mode.

## DONE when

The CI trace proves both the vulnerability and the secure invariant deterministically.
