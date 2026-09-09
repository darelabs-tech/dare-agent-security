# task-040 — Implement SIMULATED adapter

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Construct an evidence bundle in memory from a named behaviour, and let the evaluator reach its own conclusion about it.

## Files changed

- `crates/dare-a2a-security/src/simulated.rs` (`SimulatedAdapter`, `stage`)
- `crates/dare-a2a-security/src/source.rs` (`ReferenceBehavior`, 37 variants)

## A behaviour is not a verdict

`ReferenceBehavior::TaskSubstituted` says the task id changed under an exchange. It does not say the run should FAIL, and nothing in `simulated.rs` decides that. The evaluator reads the constructed bundle exactly as it reads an imported document.

That separation is what makes the paired corpus worth having. If the staging function also declared the expected outcome, every pair would test whether the fixture author and the evaluator agreed about a label rather than whether the evaluator can see a substitution.

`the_staged_bundle_carries_no_expected_outcome` asserts the rendered bundle carries no verdict-shaped field. During execution this test initially banned the bare word `expected`, which matched the policy's own legitimate `expected_audience` and `expected_provider` — approvals, not outcomes. It was narrowed to verdict-shaped names, which is the same substring trap that cost Cycle 013 a red build.

## `HarnessFailure` fails

Staging `HARNESS_FAILURE` returns an error rather than a bundle. A staged harness failure that quietly produced a clean bundle would test the opposite of what it is for.

## Two wire-format defects found here

`serde`'s `SCREAMING_SNAKE_CASE` rename turns `JsonRpc` into `JSON_RPC` and `OAuth2AuthorizationCode` into `O_AUTH2_AUTHORIZATION_CODE`, neither of which any real A2A document carries. `as_str()` and the wire representation disagreed, so a document written with either spelling was readable by only half the engine.

Both are now pinned by explicit `#[serde(rename)]`, and `every_taxonomy_is_spelled_the_same_way_on_the_wire_and_in_prose` covers the whole class of nine closed enums rather than the two instances that happened to be caught.

## One behaviour that staged nothing

`DuplicateNonIdempotentAction` originally used `summarize`, which the base policy declares idempotent — so the repeat was genuinely proven safe and the behaviour crossed no boundary. It now uses `send-invoice`, with a matching skill grant and card skill so the exchange is otherwise legitimate.

## Commands executed

```
cargo test -p dare-a2a-security --lib simulated::
cargo test -p dare-a2a-security --lib source::
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

14 simulated tests and 15 source tests passing; all 37 reference behaviours reachable.

## Evidence

```
cargo test -p dare-a2a-security --lib simulated::
test result: ok. 14 passed; 0 failed
```

## Review result

**REVIEW PASS**
