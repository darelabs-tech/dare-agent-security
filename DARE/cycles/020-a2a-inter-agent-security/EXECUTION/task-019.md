# task-019 — Implement bounded Agent Card importer

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Read a local Agent Card through the gate, in the order that makes each check meaningful.

## Files changed

- `crates/dare-a2a-security/src/harness.rs` (`StaticAdapter`, `LocalDocumentKind`)

## The order matters

1. `admit_bytes` — charge the budget
2. `enforce_document_size` — refuse before `serde_json` sees the bytes; a 40 MB card refused after parsing has already been parsed
3. parse to `Value`
4. `assert_no_hostile_fields` — sweep every depth, including objects no model has a field for
5. deserialize to `AgentCard` with `deny_unknown_fields`
6. `validate`

Step 4 runs on the untyped value on purpose. A hostile field placed where nothing will decode it is still a field in a document the engine is about to accept, and step 5 would have dropped it silently.

## Classification by name, never by content

`LocalDocumentKind::classify` reads the filename suffix. Sniffing the content to decide which parser runs would give an attacker a say in that choice, and every parser has a different attack surface. An unrecognised name is refused rather than guessed at.

Path resolution is checked twice: the scenario's file names are refused if they are path-shaped, and the resolved path must still be under the root — a symlink can leave a directory without the name ever looking like it does.

The adapter opens files and writes none.

## Commands executed

```
cargo test -p dare-a2a-security harness
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
