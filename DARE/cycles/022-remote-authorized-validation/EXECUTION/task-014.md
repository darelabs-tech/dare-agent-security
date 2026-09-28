# task-014 — Implement the `Authorization` model and `verify` rules 1–16

**Status:** DONE  
**Complexity:** HIGH

## Result

`authorization::verify` runs the 16 rules of BLUEPRINT §4.5 in order and returns the
first `AuthorizationRefusal`. It performs no I/O except reading the credential through
the injected `env` lookup, so no DNS lookup and no socket can happen before it returns.

- `VerifiedAuthorization` has private fields and no public constructor.
- The credential is handed over exactly once (`take_credential`).
- Two refinements of the Blueprint, both stricter:
  - `target_owner`/`approved_by` must be 1–200 printable characters;
  - the plan's `check_shape` runs inside rule 13.

## Tests

There is one test per rule, `rule_01_version` … `rule_16_credential`. They include:
- the window edges: `now == not_before` is allowed, `now == not_after` is refused;
- a scenario whose engine digest drifted from the grant;
- all four mandatory prohibitions;
- a plan whose limits exceed its authorization's.

Also:
- `a_consistent_lab_authorization_verifies`
- `rules_run_in_order`

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets -- -D warnings` green
- `cargo test -p dare-remote-validation`: 74 passed
- No dependency change
