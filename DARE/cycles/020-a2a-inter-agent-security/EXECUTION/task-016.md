# task-016 — Define push-notification configuration safety model without network access

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Judge a callback configuration as a document, and reach none of the places it names.

## Files changed

- `crates/dare-a2a-security/src/push_notification.rs` (new — `PushNotificationConfig` and its assessment)

## The boundary, made structural

A push-notification configuration is the one A2A surface whose entire content is a place to send data. The temptation to check whether the endpoint is live is exactly what this cycle forbids: *webhook URL != permission to connect*.

Nothing in this module resolves, probes or connects. The crate has no HTTP dependency at all, and two tests in `lib.rs` hold that line rather than a comment — `this_crate_declares_no_network_dependency_of_its_own` lists eighteen forbidden dependencies, and `no_constant_in_this_crate_holds_a_reachable_endpoint` asserts no constant carries one.

The assessment compares the configured destination against `PushNotificationPolicy::approved_destinations` and the configured sensitivity ceiling against `max_sensitivity`. Both are string and enum comparisons against a local policy; neither requires the destination to exist.

`MAX_STATE_CHANGES = 0` and `EXTERNAL_EGRESS_BYTES = 0` in `limits` are the numeric statement of the same thing.

## Commands executed

```
cargo test -p dare-a2a-security push_notification
cargo test -p dare-a2a-security --lib limits
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

6 tests passing in the module, plus the two crate-level boundary tests.

## Evidence

```
cargo test -p dare-a2a-security --lib push_notification::
test result: ok. 6 passed; 0 failed
```

## Review result

**REVIEW PASS**
