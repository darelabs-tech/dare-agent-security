# task-015 — Define extension declaration/use trust boundary

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Distinguish an extension that was declared from one that was approved, and both from one that carries authority.

## Files changed

- `crates/dare-a2a-security/src/extension.rs` (new — the extension assessment)

## Three separate questions

`CardExtension` carries `extension_id`, `required` and `claims_authority`. `ExtensionPolicy` carries the approved set and, separately, the set that may bear authority. That gives three questions an evaluator asks independently:

1. Was the extension in use declared by the card at all?
2. Is a declared extension one local policy approves?
3. Does a required extension claim authority nobody granted it?

*extension declaration != extension authority* is exactly the gap between (1) and (3). An extension the card declares is a description of a capability; an extension that claims authority is asserting a right, and the card is not the thing that grants rights.

`authority_bearing_extensions` is empty in the staged base policy, so an extension that claims authority is unapproved by default. Failing closed here matters more than usual: an extension is precisely the mechanism by which a peer extends what the protocol lets it say.

## Commands executed

```
cargo test -p dare-a2a-security extension
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

8 tests passing.

## Evidence

```
cargo test -p dare-a2a-security --lib extension::
test result: ok. 8 passed; 0 failed
```

## Review result

**REVIEW PASS**
