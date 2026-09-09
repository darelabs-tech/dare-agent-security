# task-027 — Implement A2A message authority-boundary invariant without duplicating Cycle 013

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

I06 — decide whether peer-controlled content stayed data, without re-deciding what Cycle 013 already owns.

## Files changed

- `crates/dare-a2a-security/src/invariant.rs` (the evaluator, its violations and its `applies_to` arm)
- `crates/dare-a2a-security/src/observation.rs` (the context this evaluator reads)
- `crates/dare-a2a-security/src/simulated.rs` (the reference behaviours that stage it)

## The ownership line

Cycle 013 owns generic prompt injection: whether a span of text is an injection attempt, how it is classified, and what verdict that carries. Cycle 020 does not absorb that authority and does not restate it.

What this invariant asks is narrower and A2A-specific: **did peer-controlled content reach a position where it directed behaviour?** That is a fact about the local consumer, recorded in `MessagePart::treated_as_instruction`, not a judgement about the content's text. This engine never inspects the content for hostility — it only inspects where the content went.

*peer content != privileged instruction* stated this way needs no classifier, and needs none of Cycle 013's machinery. It also cannot disagree with Cycle 013, because it is answering a different question.

`peer_content_reaching_authority_fails_and_names_the_parts` asserts the violation names the parts, so an operator can find them.

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
