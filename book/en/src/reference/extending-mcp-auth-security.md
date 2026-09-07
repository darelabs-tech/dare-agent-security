# Extending MCP Auth Security Validation

This page is the contract for adding a corpus vector, a lab scenario, a
property, a schema field, a trace or an invariant evaluator to the Cycle 018
MCP authentication and authorization engine. Every rule here exists because
breaking it would let a validator report something it has not established.

## Non-negotiables

1. **No expected verdict in a fixture.** A fixture describes how a reference
   deployment *behaves*; the evaluator decides what that means. Field names such
   as `expected_verdict`, `verdict`, `should_fail`, `should_pass` and
   `expected_outcome` are refused at any depth, a scenario's invariant spec
   carries the invariant and nothing else, and the expected outcome of each lab
   lives in the test register that runs it — never in the fixture. A fixture
   that could state its own outcome would reduce the evaluator to agreeing with
   whoever wrote it.
2. **No credential material, ever.** An auth fixture is ids, labels, claim
   structures, trust classes and digests. `access_token`, `id_token`,
   `refresh_token`, `authorization_code`, `client_secret`, `private_key`,
   `api_key`, `password`, `cookie`, `bearer` and their siblings are refused at
   any depth, and a value shaped like a real credential is refused wherever it
   appears. Detection is anchored on *shape*, so the sentence "an inbound bearer
   credential must not become the authority for an upstream call" stays writable
   while a real bearer credential does not.
3. **No endpoint, issuer URL or provider.** `token_endpoint`, `jwks_uri`,
   `issuer_url`, `introspection_endpoint`, `registration_endpoint`,
   `resource_metadata_url`, `remote`, `command` and their siblings are refused at
   any depth, and so is any value carrying a URL scheme. There is no code path
   behind them, and adding one is a design change, not a field.

   Issuers, resources and endpoints are a `SyntheticUri`, a type that **cannot
   express a URL**. The check runs in `new()` and again in a hand-written
   `Deserialize` impl, because a derived one would have let a document through
   the constructor's back door.
4. **Nothing is ever fetched, exchanged or verified.** A vector may *describe* a
   mixed-up issuer, a mis-audienced token, a downgraded PKCE method or a
   forwarded credential. It must never cause one. If your change adds a code
   path that could open a connection, perform a login, exchange an authorization
   code, fetch metadata or a key set, introspect a token or register a client, it
   is out of scope for this cycle. Do not add an HTTP client, an OAuth crate, a
   JWT library or a TLS stack.
5. **A validity state is not a verification.** `TokenValidityState` records what
   a verifier reported. Nothing here verifies a signature, and no evaluator may
   start doing so. A token with no recorded verification evidence is a gap, and
   must be reported as one rather than assumed valid or assumed invalid.
6. **Closed enums only.** Every taxonomy — scenario class, trust class, evidence
   source, protocol revision class, token validity state, registration trust,
   credential class, code-challenge method, harness error kind, invariant,
   reference behavior — is a closed set with an unknown value failing closed. Do
   not add an open string field where an enum belongs, and do not add a fallback
   branch that treats an unknown value as benign. A trust class that could not
   be read is exactly the one that must not be assumed authenticated.
7. **Prove from declarations, never by access.** An audience mismatch is
   established by comparing declared claim fields, not by presenting a token
   anywhere. If your fixture would need to reach something real to make its
   point, the fixture is wrong.
8. **Absence is never satisfaction.** A missing claim does not satisfy a
   mandatory clause, a missing observation does not produce a `PASS`, and a
   corpus vector that could not be resolved is refused rather than treated as
   absent. Use `McpAuthCorpus::resolve`, never `get`.

## Adding a corpus vector or lab scenario

Both are generated from the same lab table, which is what keeps a vector from
claiming a surface its invariant does not report under. Add your row to
`LABS` in `scripts/k18/gen_mcp_auth_scenarios.py` and regenerate everything:

```bash
python scripts/k18/gen_mcp_auth_scenarios.py
python scripts/k18/gen_mcp_auth_corpus.py
python scripts/k18/gen_mcp_auth_scenarios.py --check   # what CI runs
python scripts/k18/gen_mcp_auth_corpus.py --check
```

A lab row declares its number, title, surface and property, the invariant it is
judged under, a reference behavior, and the mutation function that produces it.

**Pair it.** Every vulnerable lab must differ from a compliant control by
**exactly one mutation**. That is what makes a verdict name a cause rather than
a difference, and `the_paired_labs_differ_only_in_the_field_under_test` enforces
it. If your mutation changes two things, you have written two labs.

**Give it a control that is not the narrowest one.** Where the compliant path
has more than one legitimate shape, add a second control. Client registration
has one for pre-registration and one for a client metadata document; credential
separation has one for a distinct credential and one for a recorded, authorized
exchange. Without them the invariant is satisfiable only by the narrowest
legitimate flow, which is a false positive waiting to happen.

**A vector the loader cannot admit is not a vector.** Lab 022 asks for a step-up
retry past the approved ceiling; it exists to be refused by the schema, so the
corpus generator skips it. A vector the corpus cannot load would make the corpus
unloadable.

## Adding a hostile fixture

```bash
python scripts/k18/gen_mcp_auth_hostile.py
python scripts/k18/gen_mcp_auth_hostile.py --check
```

Each case isolates **one** hostile mutation against a valid baseline, and the
manifest records *why* it should be refused — never what error it should
produce. A fixture that recorded its expected error would let the parser agree
with the fixture instead of judging it.

Two rules the suite enforces that are easy to miss:

- **The refusal must not echo what it refused.** A message quoting a smuggled
  token back would persist the credential it was declining to store. An error
  log is a persistence surface like any other, and schema errors report the
  instance *path* only, never the value.
- **The refusal must not read as a verdict.** `PASS`, `FAIL` and `INCONCLUSIVE`
  must not appear in a refusal. A refusal is a statement about the document, not
  about the security of the scenario it declined to evaluate.

Check your fixture against the real admission path — the document gate, the
typed decode, *and* the structural checks a schema cannot express. Testing only
the first stage lets a fixture the engine refuses later look admitted, which is
how a hostile case turns into false coverage.

## Adding a replay trace

Traces are derived from the lab scenarios rather than written by hand:

```bash
python scripts/k18/gen_mcp_auth_traces.py
python scripts/k18/gen_mcp_auth_traces.py --check
```

Only the observed **requests** are copied. A trace carries no verdict, no
expectation and no invariant, and the schema closes the object so it cannot.

**A trace is evidence, never authority.** It must agree with the approved
scenario on the authorization-relevant projection — method, name, resource —
before any evaluator sees it. Do not weaken `assert_requests_bound` to make a
trace fit; a trace that restates a request with wider semantics under the same
`scenario_id` is the defect this check exists for.

Routing metadata is deliberately left free to disagree, because that
disagreement is what the binding invariants judge. Do not bind it.

## Adding an invariant evaluator

The registry is **fifteen** invariants. It was fourteen at merge; the
post-merge review added `SELF_REPORTED_METADATA_NOT_AUTHORITY`, because the
self-reported metadata boundary was being *evaluated* correctly and *filed*
under `INBOUND_CREDENTIAL_NOT_REUSED_AS_UPSTREAM_AUTHORITY` — an invariant about
forwarding a caller's credential upstream, which is a different problem with a
different fix.

Adding a sixteenth is a design change requiring approval, not a code change. But
the count is not the thing being protected: a finding that does not name what it
is about sends an operator to the wrong place, and preserving a number at that
cost is not a saving.

If what you want to check is a property of a *request* — what was routed, what
was presented, what was performed — it belongs to one of the fifteen. If it is
a property of the evidence itself, it may belong where the self-reported
identity boundary lives: checked by `run_scenario` on every trial rather than
selected by a scenario.

That distinction is load-bearing. Promotion of self-description to authority is
wrong in any scenario that carries identity evidence, not only in one that names
it. Making it selectable would mean every scenario that did not select it kept
reporting `PASS` on a target that had already turned a name into a principal.

An evaluator must:

- return **every** independent violation, not the first. One flow can mix up the
  issuer, present a token for the wrong resource and forward a credential
  upstream at once, and reporting one of them understates what was seen;
- attach `deciding_event_digests` to each violation. A finding with no deciding
  evidence is an assertion, not a finding;
- name its **subject** — which issuer, which principal, which request. "An issuer
  was wrong" is not actionable;
- declare a positive PASS coverage contract, so a run that observed none of the
  channels the invariant needs reports `INCONCLUSIVE` rather than `PASS`.

Order matters inside `evaluate`: harness error, then violations, then coverage.
Checking coverage first would let a run with a real violation report
`INCONCLUSIVE` because some unrelated channel was missing — hiding a finding
behind a gap.

## Adding a property or touching the profile

Cycle 018 properties live in the **v1** MCP registry, not the v2 Agentic one.
That placement is deliberate: these are MCP protocol and OAuth surfaces, not
agent behaviours, and putting them in v2 would create an eleventh Agentic risk
family or force an exclusion rule to hide one. Authentication is not an Agentic
risk family.

Two rules about coverage semantics:

- **Do not move an existing denominator.** A coverage percentage is a fraction
  whose denominator is a profile's property count. Changing an earlier profile
  makes every assessment already filed against it mean something different from
  what it meant when it was produced, and nothing about the number looks wrong.
- **Classify your predicate correctly.** A predicate describing the target's
  *shape* yields `NOT_APPLICABLE` when false. A predicate describing an auth
  *control or evidence* yields `NOT_TESTED` — a gap. Putting a control in the
  first category relabels a gap as an exemption, which AC-08 forbids.

And do not reach the same outcome through the requirement level. Only `REQUIRED`
properties feed the required-coverage ratio, so marking a control-gated property
`CONDITIONAL` would print a gap that counted toward nothing. Every property in
`mcp-auth-hardening-2026` is `REQUIRED` for that reason.

## Standards discipline

MCP `2026-07-28` is the baseline. AuthZEN 1.0 is normative where applicable.
COAZ and COAZ-MCP are `DRAFT`, `openid/authzen#603` is an `OPEN_PROPOSAL`, and
DPoP, workload identity federation, ID-JAG, standardized token exchange and
Enterprise-Managed Authorization are `FUTURE`.

Do not promote a status. The provenance validator pins each source's status and
rejects a mapping claiming `NORMATIVE`, and it rejects conformance claims
outright — a bounded run is not a standards assertion. If an upstream status has
genuinely changed, re-verify it and record the verification; do not edit the pin.

## Reuse, do not rebuild

- **Cycle 001** supplies the evidence, verdict and redaction model.
- **Cycle 002** supplies `CURRENT_WIRE_REVISION` and `LEGACY_WIRE_REVISION`,
  re-exported and never redefined.
- **Cycle 003** decides authorization-to-execution integrity. Do not build a
  second engine for it; `compat.rs` composes with it.
- **Cycle 009** supplies the execution budget and kill switch for local-synthetic
  runs.
- **Cycle 015** supplies `PrincipalKind`. Two identity models that must agree and
  live in different crates eventually disagree, and the disagreement would be
  about who is allowed to do what.

## Before you open a PR

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python scripts/k18/gen_mcp_auth_schemas.py --check
python scripts/k18/gen_mcp_auth_scenarios.py --check
python scripts/k18/gen_mcp_auth_corpus.py --check
python scripts/k18/gen_mcp_auth_traces.py --check
python scripts/k18/gen_mcp_auth_hostile.py --check
python scripts/run-ci-job-locally.py .github/workflows/ci.yml mcp-auth-security-2026
```

The CI workflow triggers on PR open only, so the branch must be complete and
locally validated before the PR exists. Do not open a draft PR to see whether CI
passes.

## Related

- [MCP 2026 Authentication and Authorization Validation](../concepts/mcp-auth-security.md)
- [Adding Security Properties](adding-security-properties.md)
- [Exit Codes](exit-codes.md)
