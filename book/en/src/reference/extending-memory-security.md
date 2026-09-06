# Extending Memory Security Validation

This page is the contract for adding a corpus vector, a lab scenario, a
property, a schema field or an invariant evaluator to the Cycle 016
memory-security engine. Every rule here exists because breaking it would let a
validator report something it has not established.

## Non-negotiables

1. **No expected verdict in a fixture.** A fixture describes how a reference
   agent *behaves*; the evaluator decides what that means. Field names such as
   `expected_verdict`, `verdict`, `should_fail`, `should_pass` and
   `expected_outcome` are refused at any depth, a scenario's invariant spec
   carries the invariant and nothing else, and the expected outcome of each lab
   lives in the test that runs it — never in the fixture. A fixture that could
   state its own outcome would reduce the evaluator to agreeing with whoever
   wrote it.
2. **No credential material, ever.** A memory fixture is ids, labels, digests
   and logical times. `api_key`, `token`, `access_token`, `password`,
   `client_secret`, `private_key`, `secret`, `cookie` and their siblings are
   refused at any depth, and a value shaped like a real credential is refused
   wherever it appears. Detection is anchored on *shape*, so the sentence
   "memory holding a bearer token must not become policy-authoritative" stays
   writable while a real bearer credential does not.
3. **No store, provider or endpoint.** `store_url`, `endpoint`,
   `connection_string`, `vector_db`, `mcp_server`, `provider`, `remote` and
   their siblings are refused at any depth. There is no code path behind them,
   and adding one is a design change, not a field.
4. **Nothing is ever persisted.** A vector may *describe* a poisoned write, a
   cross-tenant recall or an expired item reaching a decision. It must never
   cause one. If your change adds a code path that could write to a store, open
   a connection or reach a provider, it is out of scope for this cycle.
5. **Closed enums only.** Every taxonomy — source kind, trust class, lifecycle
   state, scenario class, poisoning family, invariant, reference behavior — is a
   closed set with an unknown value failing closed. Do not add an open string
   field where an enum belongs, and do not add a fallback branch that treats an
   unknown value as benign. A memory item whose trust class could not be read is
   exactly the item that must not be assumed benign.
6. **Prove from declarations, never by access.** A tenant crossing is
   established by comparing declared tenant labels. If your fixture would need
   to read something real to make its point, the fixture is wrong.
7. **Logical time only.** Lifecycle facts come from the scenario's declared
   evaluation time. A verdict that moved with the machine's clock would make a
   recorded digest meaningless.

## Adding a corpus vector

The corpus is generated, not hand-edited. Add your entry to
`scripts/gen-memory-security-corpus.py` and regenerate:

```bash
python scripts/gen-memory-security-corpus.py
python scripts/gen-memory-security-corpus.py --check   # what CI runs
```

An entry must declare:

- `class` — `MEMORY_ATTACK` or `BENIGN_CONTROL`
- `surface` — one of the five surfaces, and it must be the surface that both the
  declared invariant *and* the declared family belong to; a vector filed under a
  family it does not exercise would overstate per-surface coverage
- `property` — one of the six `AGENT.MEMORY.*` properties
- `family` — one of the twelve poisoning families
- `source_kind` and `trust` — where the memory context came from
- `preconditions` — must include `memory_store_present`; without persisted
  memory there is no Cycle 016 question to ask
- `reference_behavior` — a behavior, never a verdict. An attack declaring
  `COMPLIANT` is a control, not an attack, and is refused; a control declaring a
  boundary-crossing behavior is refused for the mirror reason
- `safety_class` — always `SYNTHETIC_NOOP`
- `standards` and `provenance` — attribution with its own upstream status

Registry digests are computed over the same key-sorted JSON the Rust loader
hashes, so a hand-edited vector fails verification instead of loading quietly.

**Add a control with every attack.** A surface with only attack vectors lets an
over-strict engine look perfect while failing every legitimate use of that
surface. Controls are a correctness requirement, not balance. A control may show
legitimate *activity* — an authorized update, a recall that changed nothing —
not only inaction; a control restricted to doing nothing proves nothing about
whether real use survives the engine.

## Adding a lab scenario

Labs are generated too:

```bash
python scripts/gen-memory-security-scenarios.py
python scripts/gen-memory-security-scenarios.py --check
```

Every lab derives from one shared store, context and policy. **Keep the pairing
exact**: a PASS lab and its FAIL partner must differ in exactly one thing — the
reference behavior — so a verdict difference is attributable to that one thing.
A test asserts this directly; if you "fix" a failing lab by also changing its
store or policy, that test will tell you the pair has stopped isolating
anything.

Register the lab and its approved outcome in
`crates/dare-memory-security/tests/lab_scenarios.rs`. The register and the
fixture meet only at the assertion.

## Adding a hostile fixture

```bash
python scripts/gen-memory-security-hostile-fixtures.py
python scripts/gen-memory-security-hostile-fixtures.py --check
```

Isolate exactly one hostile mutation against the valid baseline, so a refusal
names one cause rather than a document that was wrong in six ways. Record the
document kind and a human reason in the manifest — never an expected error, for
the same reason a corpus entry carries no verdict.

These fixtures are deliberately absent from `registry.json`. They are not corpus
vectors, and loading the corpus must ignore them entirely.

## Adding an invariant

An invariant is a deterministic comparison of typed fields. Adding one means:

1. a variant on `MemoryInvariantType`, with its surface;
2. a **positive coverage contract** in `coverage.rs` naming the observation
   channels a run must actually have produced before the invariant may report
   `PASS`, and the operator-facing reason a missing channel makes the question
   undecidable;
3. an evaluator that returns every independently observed violation as a list,
   never a first match;
4. paired PASS/FAIL fixtures and a benign control.

Ask whether the invariant is about what memory *is* or what it *did*. If it is
about what memory did, it needs an exercise channel — a recall or an influence —
because a clean-looking run where nothing was tried is not a clean run.

## Adding a property

Properties live in the shared v2 registry and are additive only. The two
properties that predate this cycle keep their identifiers *and* their
applicability predicates: a changed identifier silently stops matching every
prior assessment, and a changed predicate moves which targets a property applies
to, which moves a denominator without any profile being edited.

A new property must not be selected by two profiles. One property counting
toward two denominators is how a coverage number quietly inflates.

Mark a property `CONDITIONAL` rather than `REQUIRED` when a target may
legitimately have nothing to answer. A target that never recalls memory has no
recall boundary; marking it `REQUIRED` would turn "not applicable" into a gap,
and a system that honestly declared no recall would score worse than one with no
memory at all.

## What belongs to Cycle 017 instead

Do not add any of the following here:

- embedding retrieval, similarity search or reranking;
- document retrieval ACLs or vector-store authorization;
- cross-document retrieval testing or chunk-level isolation.

Cycle 016 is about persisted memory and context *state*. Cycle 017 is about
retrieval. Blurring the two would let a memory report be read as covering what a
retriever will hand an agent tomorrow, which it does not.

Equally out of scope: OAuth, OIDC, JWT verification, JWKS, identity providers,
PDPs and remote AuthZEN. Those belong to Cycle 018.

## Before you open a pull request

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python scripts/gen-memory-security-corpus.py --check
python scripts/gen-memory-security-scenarios.py --check
python scripts/gen-memory-security-hostile-fixtures.py --check
python scripts/run-ci-job-locally.py .github/workflows/ci.yml memory-security-2026
```

The last command runs the real workflow job rather than an equivalent by hand,
which is the point: a gate that is only ever approximated locally is a gate
nobody has actually run.
