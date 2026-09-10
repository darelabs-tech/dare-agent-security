# task-020 — Implement bounded captured A2A exchange importer

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Read a local capture. Analyse it. Re-send nothing.

## Files changed

- `crates/dare-a2a-security/src/capture.rs` (new — `A2aCapture`, `ReplayAdapter`)

## What REPLAY means here

REPLAY means analysing a capture that already exists on disk. It does not mean replaying traffic, and there is nothing in this module that could: no client, no socket, no HTTP dependency in the crate.

## The capture's own policy is discarded

`ReplayAdapter` drops any policy recorded inside the capture and uses the local one. A capture is evidence about what happened; it is not an approval, and a capture that could carry its own policy would let a recorded run declare its own approvals — the same failure as a fixture declaring its own verdict, one layer down.

Everything else in the capture — exchanges, peers, cards, verification records — is imported through the same admission and refusal path as any other document.

## Commands executed

```
cargo test -p dare-a2a-security capture
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
