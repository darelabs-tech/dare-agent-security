# task-018 — Implement hostile secret/path/bidi/executable/remote-action refusal layer

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Refuse the documents this engine must not read, and — just as hard — read the ones it must.

## Files changed

- `crates/dare-a2a-security/src/schema.rs` (new — the document gate)
- `crates/dare-a2a-security/src/canonical.rs` (new — `assert_safe_identifier` and the digest helpers)

## Five lists, and the one that decides whether the gate is usable

- `FORBIDDEN_CREDENTIAL_FIELDS` (26) — a card carrying a secret is a card that should never have been written
- `FORBIDDEN_EXECUTABLE_FIELDS` (16) — a description of what a peer can do is not a description of what to run
- `FORBIDDEN_FETCH_FIELDS` (14) — fields whose **name asks for an action**
- `FORBIDDEN_VERDICT_FIELDS` (12) — the evaluator is the only verdict authority
- `CREDENTIAL_SHAPED_VALUES` (12) and `FORBIDDEN_URL_SCHEMES` (9)

The fetch list is the one that matters most, and what it does **not** contain is the point: `url`, `endpoint`, `issuer`, `jku`, `jwks_uri`, `token_endpoint`, `webhook`, `callback_url` and `agent_card_url` are all absent. Those name places, and this engine goes to none of them. `the_fetch_list_refuses_actions_and_not_locations` asserts both halves — that every one of those nine stays readable, and that `fetch`, `download`, `auto_resolve` and `probe_webhook` are refused.

A gate that refused locations would refuse every real Agent Card and be switched off by the first person who hit it, taking the credential and executable checks with it.

`FORBIDDEN_URL_SCHEMES` omits `http`, `https`, `grpc` and `grpcs` for the same reason: those are what an A2A interface *is*. What it refuses is `file://`, `javascript:`, `data:` and the rest — schemes that could not be an A2A interface and have no business in one.

## Two defects found and fixed in this task

`CREDENTIAL_SHAPED_VALUES` is all-lowercase and compared against a lowercased string. Cycle 018 shipped a list containing `AKIA` and `eyJhbGci` compared against a lowercased haystack — the list looked right and matched nothing. The comment records why.

`contains_bearer_credential` is anchored on **shape**, not on the word: `bearer ` followed by at least sixteen credential characters. A word-ban version failed against this crate's own documentation, which discusses bearer tokens in prose. A gate that cannot describe itself is a gate someone will weaken.

`normalize_field` strips non-alphanumerics before comparing, so `api-key`, `api key` and `apiKey` are one field rather than three.

## Commands executed

```
cargo test -p dare-a2a-security schema
cargo test -p dare-a2a-security canonical
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

16 schema tests and 9 canonical tests passing.

## Evidence

```
cargo test -p dare-a2a-security --lib schema::
test result: ok. 16 passed; 0 failed
```

## Review result

**REVIEW PASS**
