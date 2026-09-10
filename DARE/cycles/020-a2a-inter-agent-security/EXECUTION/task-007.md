# task-007 — Define closed A2A message/task/context envelope model

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Model the exchange envelope and its parts so correlation identifiers stay correlation identifiers.

## Files changed

- `crates/dare-a2a-security/src/message.rs` (new — `Exchange`, `MessagePart`, `ExchangeLog`)

## Decisions

`task_id`, `context_id` and `initiating_principal` are three separate optional fields. A taskId correlates; it does not identify a principal, and *taskId match != principal/context match* is only enforceable because the third field exists to disagree with the first two.

`tenant_claim` is documented as a routing value the sender chose, carrying *tenant routing value != proof of tenant authorization* into every read site.

`MessagePart` carries a bounded summary rather than content, plus `data_labels` and `treated_as_instruction`. Retaining full peer content would put attacker-chosen text into every artifact this engine writes; the summary is capped at `MAX_EVIDENCE_TEXT_BYTES`.

`treated_as_instruction` is the single field I06 turns on, and it records what the local side did rather than what the peer asked for — *peer content != privileged instruction* is a fact about the consumer, not about the message.

`ExchangeLog::validate` refuses two exchanges under one message id: a repeat is a distinct message, and collapsing them would hide the replay this engine exists to see.

## Commands executed

```
cargo test -p dare-a2a-security message
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

13 tests passing.

## Evidence

```
cargo test -p dare-a2a-security message::
test result: ok. 13 passed; 0 failed
```

## Review result

**REVIEW PASS**
