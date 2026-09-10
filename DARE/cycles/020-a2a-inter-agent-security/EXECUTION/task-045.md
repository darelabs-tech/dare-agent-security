# task-045 — Build A2A-LAB replay/protocol/extension/push corpus

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Cover the four remaining surfaces, each of which turns on a distinction the protocol itself does not enforce.

## Files changed

- `crates/dare-a2a-security/src/corpus.rs`
- `crates/dare-a2a-security/tests/a2a_lab.rs`

## Entries

**Replay (I11).** `037` control — a repeated state change carrying an idempotency key; `038` a repeated state change with no idempotency evidence at all; `039` a duplicate action on a skill policy never declared idempotent; `040` one message id used twice, refused.

`037` and `039` are the pair that makes this surface meaningful: both are repeats, and only one is safe. *Message retry != safe replay* cuts both ways, and an engine that reported `037` would train an operator to ignore it.

`040` is refused rather than evaluated. A repeat is a distinct message; collapsing two under one id would hide the replay this engine exists to see, so the bundle is rejected at admission instead of quietly deduplicated.

**Protocol (I12).** `041` control; `042` a version below the policy floor; `043` a version outside the approved set; `044` a transport policy does not approve. `042` is *protocol compatibility != permission to downgrade*: the peer and the local side can both speak 0.9.0, and that is not permission to.

**Extensions (I13).** `045` an extension in use the card never declared; `046` a declared extension local policy does not approve; `047` a required extension claiming authority nobody granted it. `045` and `046` are the two halves of *extension declaration != extension authority*, and `047` is the case where the extension asserts the authority itself.

**Push notification (I14).** `048` a callback destination policy never approved; `049` a callback configured to carry data beyond the approved scope; `052` a webhook registered by an exchange to a destination nobody approved.

Every destination in these three is inert metadata. Nothing in this crate resolves one, and `no_constant_in_this_crate_holds_a_reachable_endpoint` plus the dependency test in `lib.rs` are what make that structural rather than a promise — *webhook URL != permission to connect*, enforced by the absence of anything that could connect.

**Cross-cutting.** `050` one exchange crossing three independent boundaries at once, held to reporting all three by its own test.

## Commands executed

```
cargo test -p dare-a2a-security --test a2a_lab
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

All entries behave as their class requires.

## Evidence

```
test a_multi_violation_exchange_reports_every_boundary_it_crossed ... ok
test every_attack_is_seen_by_the_invariant_it_was_built_for ... ok
test no_control_is_reported_by_the_invariant_it_exercises ... ok
```

## Review result

**REVIEW PASS**
