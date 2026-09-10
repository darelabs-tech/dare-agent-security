# task-038 — Implement STATIC adapter

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Read local Agent Cards, traces, verification records and policy from a directory, and write nothing.

## Files changed

- `crates/dare-a2a-security/src/harness.rs` (`A2aAdapter`, `LocalDocumentKind`, `StaticAdapter`)

## The adapter contract

`A2aAdapter` has four members: `mode()`, `collect()`, `evidence_is_synthetic()` and `control_snapshot()`.

`evidence_is_synthetic()` **defaults to `true`**. Every adapter that stages anything leaves the default alone, and only one that genuinely reads production evidence overrides it. A report must never present a constructed bundle as production evidence, and the safe default is the one that says so.

## Classification by name, never by content

`LocalDocumentKind::classify` reads the filename suffix — `card.json`, `peers.json`, `trace.json`, `peer-auth.json`, `message-auth.json`, `delegation.json`, `push.json`, `policy.json`. An unrecognised name is refused rather than guessed at.

Sniffing the content to decide which parser runs would give an attacker a say in that choice, and every parser has a different attack surface.

## Two path checks, because one is not enough

The scenario's file names are refused if they are path-shaped, by `assert_safe_identifier`. The resolved path is then checked to still be under the root — a symlink can leave a directory without the name ever looking like it does.

`StaticAdapter` opens files. It creates, writes, moves and deletes none.

## Commands executed

```
cargo test -p dare-a2a-security --lib harness::
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

8 tests passing.

## Evidence

```
cargo test -p dare-a2a-security --lib harness::
test result: ok. 8 passed; 0 failed
```

## Review result

**REVIEW PASS**
