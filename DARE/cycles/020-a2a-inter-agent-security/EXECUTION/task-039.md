# task-039 — Implement offline REPLAY adapter that never re-sends captured traffic

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Analyse a capture that already exists. Re-send nothing.

## Files changed

- `crates/dare-a2a-security/src/capture.rs` (`A2aCapture`, `ReplayAdapter`)

## What REPLAY means in this cycle

REPLAY means reading a local capture and evaluating it. It does not mean replaying traffic, and nothing in this module could: the crate declares no HTTP client, no socket library and no TLS stack, and `this_crate_declares_no_network_dependency_of_its_own` fails if one appears.

## The capture's own policy is discarded

`ReplayAdapter` drops any policy embedded in the capture and uses the local one.

A capture is evidence about what happened. It is not an approval. A capture that could carry its own policy would let a recorded run declare its own approvals — structurally the same failure as a fixture declaring its own verdict, one layer down, and harder to notice because the capture looks like data.

Everything else — exchanges, peers, cards, verification records — is imported through the same admission and refusal path as any other local document.

## Commands executed

```
cargo test -p dare-a2a-security --lib capture::
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

8 tests passing, including one asserting a policy embedded in a capture does not reach the evaluator.

## Evidence

```
cargo test -p dare-a2a-security --lib capture::
test result: ok. 8 passed; 0 failed
```

## Review result

**REVIEW PASS**
