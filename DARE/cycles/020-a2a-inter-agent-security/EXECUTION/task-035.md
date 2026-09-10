# task-035 — Implement push-notification local-only boundary invariant

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

I14 — decide whether a callback configuration discloses no further than approved, without contacting anything.

## Files changed

- `crates/dare-a2a-security/src/invariant.rs` (the evaluator, its violations and its `applies_to` arm)
- `crates/dare-a2a-security/src/observation.rs` (the context this evaluator reads)
- `crates/dare-a2a-security/src/simulated.rs` (the reference behaviours that stage it)

## What it compares, and what it never does

The configured destination against `PushNotificationPolicy::approved_destinations`, and the configured sensitivity ceiling against `max_sensitivity`. Both are local comparisons; neither requires the destination to exist.

*webhook URL != permission to connect* is the distinction, and here it is enforced by absence rather than by rule. The crate declares no HTTP client, no TLS stack and no resolver. `this_crate_declares_no_network_dependency_of_its_own` lists eighteen dependencies that must not appear, and `no_constant_in_this_crate_holds_a_reachable_endpoint` asserts no constant carries one.

`an_unapproved_push_destination_fails_without_contacting_anything` is named for the second half deliberately. The temptation on this surface is to check whether the endpoint is live, and a test that only asserted the finding would not notice the day somebody added that check.

The corpus stages three shapes: an unapproved destination, a widened scope, and a webhook registered by an exchange rather than configured up front.

## Commands executed

```
cargo test -p dare-a2a-security --lib invariant::
cargo test -p dare-a2a-security --lib simulated::
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

24 invariant tests and 14 simulated-adapter tests passing; whole crate green.

## Evidence

```
cargo test -p dare-a2a-security --lib invariant::
test result: ok. 24 passed; 0 failed
```

## Review result

**REVIEW PASS**
