# task-005 — Define closed Agent Card/security evidence schemas

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Model the Agent Card, its interfaces, declared security schemes, skills, extensions and signature evidence as closed types that fail closed on anything unrecognised.

## Files changed

- `crates/dare-a2a-security/src/agent_card.rs` (new — `AgentCard`, `CardInterface`, `DeclaredSecurityScheme`, `CardSkill`, `CardExtension`, `CardSignatureEvidence`, `card_digest`)
- `crates/dare-a2a-security/Cargo.toml`, `src/lib.rs`

## Decisions

Every struct carries `#[serde(deny_unknown_fields)]` and every enum is closed. A card arriving with a field this engine does not model is refused rather than silently truncated: the dropped field could be the one that mattered, and an engine that drops it reports on a document nobody sent.

`CardSignatureEvidence::validate` refuses `EvidenceSource::LocalPolicy`. The local policy is the approval authority; it is not a verifier, and a card whose signature is "verified by the thing that approves it" is a card that verified itself. The asymmetry is structural rather than a rule an evaluator has to remember.

`provider` is optional and documented as a claim by the thing being judged. `card_digest()` is computed over the canonical form, so a substituted card is detectable even when every field reads plausibly.

Location fields — `CardInterface::url`, `DeclaredSecurityScheme::issuer` and `token_endpoint`, `CardSignatureEvidence::key_location` — are retained as inert metadata, documented as resolved by nothing, because a report has to be able to name where a peer said it lives.

## Commands executed

```
cargo test -p dare-a2a-security agent_card
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

11 tests in `agent_card.rs` passing; clippy clean.

## Evidence

```
cargo test -p dare-a2a-security agent_card::
test result: ok. 11 passed; 0 failed
```

## Review result

**REVIEW PASS**
