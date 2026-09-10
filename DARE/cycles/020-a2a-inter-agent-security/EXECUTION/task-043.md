# task-043 — Build A2A-LAB peer/authentication/skill/message corpus

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Cover the four surfaces where authentication is most often mistaken for authorization: peer identity, security requirement, skill grant, and message authenticity and authority.

## Files changed

- `crates/dare-a2a-security/src/corpus.rs`
- `crates/dare-a2a-security/tests/a2a_lab.rs`

## Entries

**Peer identity (I02).** `007` control; `008` a credential issued for another audience; `009` authentication verified and found invalid; `010` no authentication evidence at all; `012` two authentication records for one peer, refused because whichever an evaluator read first would decide and the two disagree; `051` a bundle with nothing to decide on in any direction.

**Security requirement (I04).** `013` control; `014` a scheme the card does not require for the skill invoked. The distinction is *declared security scheme != successful authentication*, and separately *successful authentication != skill authorization* — which is why I04 and I05 are separate entries over the same exchange.

**Skill authorization (I05).** `015` control; `016` an authenticated subject invoking a skill nobody granted it; `011` the same crossing reached from the other side, a peer acting as itself with no delegated subject.

**Message authenticity (I03).** `017` a signature verified and found invalid; `018` no signature evidence at all; `019` a *valid* signature covering a different envelope than the one observed. `019` is the entry this invariant exists for: a signature over a message is not a signature over this message, and only the covered-envelope digest tells the two apart.

**Message authority (I06).** `020` control — peer content stays data even though the peer authenticated; `021` peer-controlled content reaching a position where it directed behaviour; `022` a message carrying script-shaped executable metadata, refused at the door.

## The control that matters most here

`020` is the entry that keeps I06 honest. An engine that reported every authenticated peer's content as an instruction would catch `021` and be useless. The harness contract asserts `020` is not reported, which is the only thing separating a working authority-boundary evaluator from a broken one.

## Commands executed

```
cargo test -p dare-a2a-security --test a2a_lab
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

All entries behave as their class requires: `017`, `019`, `021` and `011` report concrete failures with deciding evidence; `018` and `010` stay undecided; `020` and the controls are not reported.

## Evidence

```
test every_attack_is_seen_by_the_invariant_it_was_built_for ... ok
test no_control_is_reported_by_the_invariant_it_exercises ... ok
test no_gap_is_reported_as_an_applicable_pass ... ok
```

## Review result

**REVIEW PASS**
