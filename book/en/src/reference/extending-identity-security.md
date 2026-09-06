# Extending Identity Security Validation

This page is the contract for adding a corpus vector, a lab scenario, a property,
a schema field or an invariant evaluator to the Cycle 015 identity-security
engine. Every rule here exists because breaking it would let a validator report
something it has not established.

## Non-negotiables

1. **No expected verdict in a fixture.** A fixture describes how a reference
   agent *behaves*; the evaluator decides what that means. Field names such as
   `expected_verdict`, `verdict`, `should_fail`, `should_pass`, `is_vulnerable`
   and `expected_outcome` are refused at any depth, a scenario's invariant spec
   carries the invariant and nothing else, and the expected outcome of each lab
   lives in the test that runs it — never in the fixture.
2. **No credential material, ever.** A credential context is an identifier, an
   owner and capability labels. `access_token`, `client_secret`, `api_key`,
   `private_key`, `password`, `bearer`, `jwt`, `jwks`, `cookie` and their
   siblings are refused at any depth, and a value shaped like a real credential
   is refused wherever it appears. Detection is anchored on *shape*, so the
   sentence "this lab issues no bearer token" stays writable while a real bearer
   credential does not.
3. **No remote target.** `url`, `endpoint`, `issuer`, `jwks_uri`, `pdp_url`,
   `authzen_url`, `mcp_server`, `provider`, `remote` and their siblings are
   refused at any depth. There is no code path behind them and adding one is a
   design change, not a field.
4. **Nothing is ever performed.** A vector may *describe* a cross-tenant read, a
   delete or a service identity acting for a user. It must never cause one. If
   your change adds a code path that could perform an operation or reach a
   provider, it is out of scope for this cycle.
5. **Closed enums only.** Every taxonomy — principal kind, delegation kind,
   source kind, trust level, invariant, reference behavior — is a closed set
   with an unknown value failing closed. Do not add an open string field where
   an enum belongs, and do not add a fallback branch that treats an unknown
   value as benign.
6. **Prove from declarations, never by access.** A tenant crossing is
   established by comparing declared tenant labels against a declared authority
   ceiling. If your fixture would need to read something real to make its point,
   the fixture is wrong.

## Adding a corpus vector

The corpus is generated, not hand-edited. Add your entry to
`scripts/gen-identity-security-corpus.py` and regenerate:

```bash
python scripts/gen-identity-security-corpus.py
python scripts/gen-identity-security-corpus.py --check   # what CI runs
```

An entry must declare:

- `class` — `IDENTITY_ATTACK` or `BENIGN_CONTROL`
- `surface` — one of the five surfaces, and it must be the surface the declared
  invariant actually belongs to; a vector filed under a family it does not
  exercise would overstate per-surface coverage
- `property` — one of the six `AGENT.IDENTITY.*` properties
- `source_kind` and `trust` — where the identity context entered
- `preconditions` — must include `principal_context_present`
- `reference_behavior` — a behavior, never a verdict; an attack declaring
  `COMPLIANT` is refused as a mislabelled control
- `expected_invariant` — which invariant the vector is filed under, used by
  tests and reporting, never by the simulator
- `provenance` — synthetic origin, author, date and license

**Pair every attack with a benign control** that differs only in the reference
behavior and the surface facts. An attack without a control proves the engine
can fail; the pair proves it can also decline to. The corpus test suite enforces
this: every invariant must be named by both an attack and a control.

**Add a false-positive regression** when your vector's subject matter uses
security vocabulary. `benign-security-vocabulary-is-not-a-violation` is the
model: an objective that legitimately discusses impersonation, escalation,
cross-tenant access and bearer credentials, which no invariant may fail on.
Reading those words is not a violation; behavior is.

## Adding a lab scenario

Lab scenarios are generated too:

```bash
python scripts/gen-identity-security-scenarios.py
python scripts/gen-identity-security-scenarios.py --check
```

Every value in a scenario must be derivable from the shared synthetic world the
generator declares — principals, authorities, tenant labels, canaries. The
simulated adapter refuses to stage a behavior the scenario cannot honestly
describe rather than inventing an identifier to make a violation appear, and
your fixture should be written so that refusal never happens.

Register the expected outcome in `tests/lab_scenarios.rs`, not in the fixture.

## Adding an invariant

Adding one means touching, in this order:

1. `IdentityInvariantType` — a new variant, its string, its `all()` entry and
   its `surface()`;
2. `coverage_contract()` — the channels a run must have observed before the
   invariant may say `PASS`, and whether it also needs an exercise channel;
3. an evaluator in `invariant.rs` returning a `Vec<IdentityViolation>` — never a
   first match, never an `Option`;
4. corpus entries: at least one attack and one benign control;
5. a lab scenario reaching it in both directions;
6. the CI job, if the invariant needs a distinct end-to-end assertion.

The compiler will find (1) and (2) for you: both are total matches over the
closed set, deliberately.

## Adding a schema field

Schemas are closed (`additionalProperties: false`) and the Rust types use
`deny_unknown_fields`. Both gates exist so a field slipping past one still has
to survive the other; add your field to both, and add a hostile fixture proving
the *absence* of the field's dangerous cousin is enforced.

Run the hostile suite after any schema change:

```bash
python scripts/gen-identity-security-hostile-fixtures.py --check
cargo test -p dare-identity-security --test hostile_fixtures
```

## Reporting wording

Any text that reaches an artifact passes a bounded-claim gate. These phrases are
refused, in every casing:

`Identity Secure`, `Authorization Secure`, `No Privilege Escalation Possible`,
`Fully Protected`, `Immune`, `guaranteed secure`, `cannot be escalated`,
`cannot be impersonated`, `AuthZEN compliant`, `COAZ compliant`.

The approved wording for a run with no observed violation is, verbatim:

> No identity-security invariant violation was observed for the tested vectors
> under the recorded conditions.

If you find yourself wanting stronger wording, the thing to change is what the
run establishes, not what the report says about it.

## Before opening a pull request

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
python scripts/gen-identity-security-corpus.py --check
python scripts/gen-identity-security-scenarios.py --check
python scripts/gen-identity-security-hostile-fixtures.py --check
python scripts/run-ci-job-locally.py .github/workflows/ci.yml identity-security-2026
```

The last one runs the real job from the workflow file. Reproducing its commands
by hand is not a substitute: the point is that the job as written passes.
