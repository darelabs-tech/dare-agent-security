# task-046 — Build hostile/refusal/admission corpus

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Eleven entries that must never reach an evaluator, and one that must.

## Files changed

- `crates/dare-a2a-security/src/corpus.rs`
- `crates/dare-a2a-security/tests/a2a_lab.rs`

## The refusals

Each is imported through the same gate a real document passes — `admit_bytes`, `enforce_document_size`, parse, `assert_no_hostile_fields`, deserialize, `validate` — so the refusal is the production path's refusal and not a test-only one.

- `006` a card larger than `HARD_MAX_DOCUMENT_BYTES`, refused before it is parsed
- `053` a card carrying `client_secret`
- `054` a card carrying `resolve_key`
- `055` a card nested past `HARD_MAX_JSON_DEPTH`
- `056` a card declaring `trusted`
- `057` a card whose `card_id` is `../../etc/passwd`
- `012` two authentication records for one peer
- `022` a message carrying `entrypoint: /bin/sh`
- `030` two delegation chains under one id
- `034` a tenant identifier carrying U+202E
- `040` one message id used twice

`every_refusal_is_refused_before_any_invariant_is_evaluated` asserts each one errors, and that the error says more than that something went wrong — an operator handed a bare failure knows a run stopped, not what to fix.

## The control that decides whether the gate is usable

`058` is a realistic Agent Card carrying two interface URLs, an OAuth issuer, a token endpoint, a JWKS `key_location`, and a declared push-notification capability. Every one of those is a place a request could go, and every one must stay readable.

This is the line the whole document gate turns on: **it refuses actions, not locations**. `resolve_key` is refused because the field name asks for something to happen. `jku`, `token_endpoint`, `issuer` and `url` are retained because they name places, and this engine goes to none of them. A gate that refused them would refuse every real Agent Card and be switched off by the first person who hit it — at which point the credential and executable checks go with it.

`058` and `054` are therefore a pair, and neither is meaningful alone.

## Note on the entries that are refused rather than reported

`012`, `030`, `034` and `040` could each have been written as findings. They are refusals instead because in every case the ambiguity is *upstream of the question the evaluator asks*: two authentication records mean the evaluator's answer depends on iteration order, and two tenant ids that render alike mean its answer depends on which one a human read. An evaluator that has to be right about a bundle nobody can read unambiguously is an evaluator that will eventually be wrong quietly.

## Commands executed

```
cargo test -p dare-a2a-security --test a2a_lab
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

11 refusals, all refused at admission with a reason; `058` admitted and evaluated without a finding.

## Evidence

```
test every_refusal_is_refused_before_any_invariant_is_evaluated ... ok
test no_control_is_reported_by_the_invariant_it_exercises ... ok
```

## Review result

**REVIEW PASS**
