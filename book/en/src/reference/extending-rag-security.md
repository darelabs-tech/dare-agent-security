# Extending RAG and Retrieval Security Validation

This page is the contract for adding a corpus vector, a lab scenario, a
property, a schema field or an invariant evaluator to the Cycle 017
retrieval-security engine. Every rule here exists because breaking it would let
a validator report something it has not established.

## Non-negotiables

1. **No expected verdict in a fixture.** A fixture describes how a reference
   retriever *behaves*; the evaluator decides what that means. Field names such
   as `expected_verdict`, `verdict`, `should_fail`, `should_pass` and
   `expected_outcome` are refused at any depth, a scenario's invariant spec
   carries the invariant and nothing else, and the expected outcome of each lab
   lives in the test that runs it — never in the fixture. A fixture that could
   state its own outcome would reduce the evaluator to agreeing with whoever
   wrote it.
2. **No credential material, ever.** A retrieval fixture is ids, labels,
   metadata, digests and scores. `api_key`, `token`, `access_token`, `password`,
   `client_secret`, `private_key`, `secret`, `cookie` and their siblings are
   refused at any depth, and a value shaped like a real credential is refused
   wherever it appears. Detection is anchored on *shape*, so the sentence "a
   retrieved document holding a bearer token must not become
   policy-authoritative" stays writable while a real bearer credential does not.
3. **No index, provider or endpoint.** `index_url`, `endpoint`,
   `connection_string`, `vector_db`, `pinecone`, `weaviate`, `qdrant`,
   `opensearch`, `elasticsearch`, `mcp_server`, `provider`, `remote` and their
   siblings are refused at any depth. There is no code path behind them, and
   adding one is a design change, not a field.
4. **Nothing is ever indexed, embedded or fetched.** A vector may *describe* a
   cross-tenant result, a disclosed protected document or a fallback that
   widened authority. It must never cause one. If your change adds a code path
   that could open a connection, reach a provider, or run an embedding model, it
   is out of scope for this cycle. Do not add an embedding dependency, do not
   download a model, do not call a provider.
5. **Nothing semantic decides anything.** No model, embedding, cosine
   similarity, reranker, fuzzy match or prose heuristic may enter the verdict
   path, and no score threshold the policy did not authorize. Scores may be
   recorded as pre-computed evidence about ordering. If your evaluator would
   need to judge whether an embedding "makes sense", it is not an invariant.
6. **Closed enums only.** Every taxonomy — source kind, trust class,
   classification level, document state, scenario class, retrieval family,
   invariant, reference behavior — is a closed set with an unknown value failing
   closed. Do not add an open string field where an enum belongs, and do not add
   a fallback branch that treats an unknown value as benign. A document whose
   trust class could not be read is exactly the document that must not be
   assumed benign.
7. **Prove from declarations, never by access.** A tenant crossing is
   established by comparing declared tenant labels, not by retrieving anything.
   If your fixture would need to read something real to make its point, the
   fixture is wrong.
8. **Absence is never satisfaction.** A missing metadata field does not satisfy
   a mandatory clause, a missing observation does not produce a `PASS`, and a
   corpus vector that could not be resolved is refused rather than treated as
   absent.

## Adding a corpus vector

The corpus is generated, not hand-edited. Add your entry to
`scripts/gen-rag-security-corpus.py` and regenerate:

```bash
python scripts/gen-rag-security-corpus.py
python scripts/gen-rag-security-corpus.py --check   # what CI runs
```

An entry must declare:

- `class` — `RETRIEVAL_ATTACK` or `BENIGN_CONTROL`
- `surface` — one of the six surfaces, and it must be the surface that both the
  declared invariant *and* the declared family belong to; a vector filed under a
  family it does not exercise would overstate per-surface coverage
- `property` — one of the six `AGENT.RAG.*` properties
- `family` — one of the twelve retrieval families
- `source_kind` and `trust` — where the corpus came from
- `preconditions` — must include `rag_present`; without retrieval there is no
  Cycle 017 question to ask
- `reference_behavior` — a behavior, never a verdict. An attack declaring
  `COMPLIANT` is a control, not an attack, and is refused; a control declaring a
  boundary-crossing behavior is refused for the mirror reason
- `safety_class` — always `SYNTHETIC_NOOP`
- `standards` and `provenance` — attribution with its own upstream status

Registry digests are computed over the same key-sorted JSON the Rust loader
hashes, so a hand-edited vector fails verification instead of loading quietly.

**Add a control with every attack.** A surface with only attack vectors lets an
over-strict engine look perfect while failing every legitimate retrieval on that
surface. Controls are a correctness requirement, not balance. A control may show
legitimate *activity* — an authorized search across two collections, a
broadening that stayed inside its authority — not only inaction; a control
restricted to returning nothing proves nothing about whether real retrieval
survives the engine.

## Adding a lab scenario

Labs are generated too:

```bash
python scripts/gen-rag-security-scenarios.py
python scripts/gen-rag-security-scenarios.py --check
```

Every lab derives from one shared corpus, context and policy. **Keep the pairing
exact**: a PASS lab and its FAIL partner must differ in exactly one thing — the
reference behavior — so a verdict difference is attributable to that one thing.
A test asserts this directly; if you "fix" a failing lab by also changing its
corpus, policy or query, that test will tell you the pair has stopped isolating
anything.

Register the lab and its approved outcome in
`crates/dare-rag-security/tests/lab_scenarios.rs`. The register and the fixture
meet only at the assertion.

## Adding a hostile fixture

```bash
python scripts/gen-rag-security-hostile-fixtures.py
python scripts/gen-rag-security-hostile-fixtures.py --check
```

Isolate exactly one hostile mutation against the valid baseline, so a refusal
names one cause rather than a document that was wrong in six ways. Record the
document kind and a human reason in the manifest — never an expected error, for
the same reason a corpus entry carries no verdict.

These fixtures are deliberately absent from `registry.json`. They are not corpus
vectors, and loading the corpus must ignore them entirely.

## Adding an invariant

An invariant is a deterministic comparison of typed fields. Adding one means:

1. a variant on `RagInvariantType`, with its surface and its property;
2. a **positive coverage contract** in `coverage.rs` naming the observation
   channels a run must actually have produced before the invariant may report
   `PASS`, and the operator-facing reason a missing channel makes the question
   undecidable;
3. an evaluator that returns every independently observed violation as a list,
   never a first match;
4. paired PASS/FAIL fixtures and a benign control.

Ask whether the invariant is about what the corpus *is* or what the retriever
*did*. If it is about what the retriever did, it needs an exercise channel — a
result set or an influence observation — because a clean-looking run where
nothing was retrieved is not a clean run.

**Prefer two channels to one where the first is a self-report.** The metadata
filter invariant reads both the retriever's admission decisions and the corpus
itself, because a retriever that records honest decisions for everything except
the document it smuggled in would otherwise satisfy the coverage contract and
leave that document unchecked.

## Adding a property

Properties live in the shared v2 registry and are additive only. Existing
properties keep their identifiers *and* their applicability predicates: a changed
identifier silently stops matching every prior assessment, and a changed
predicate moves which targets a property applies to, which moves a denominator
without any profile being edited.

The six `AGENT.RAG.*` properties report under the `RETRIEVAL` category and carry
**no risk family**. Retrieval is not an eleventh Agentic risk family, and
neither is LLM09. The Agentic risk family count is exactly ten and a test
asserts it from both the registry and the profile side. Do not add a family to a
RAG property; the schema and the validator both refuse it.

A new property must not be selected by two profiles. One property counting
toward two denominators is how a coverage number quietly inflates.

Mark a property `CONDITIONAL` rather than `REQUIRED` when a target may
legitimately have nothing to answer. A corpus holding nothing untrusted has no
promotion to answer for, and a policy designating no protected class has nothing
to withhold; marking either `REQUIRED` would turn "not applicable" into a gap
and make an honest target score worse than one that declares less about itself.

## What belongs to a neighbouring cycle instead

Do not add any of the following here:

- whether retrieved content was *followed* as an instruction — that is Cycle
  013's judgement, and this engine must not run a second prompt-injection
  evaluator;
- anything about persisted memory — that is Cycle 016's. Retrieved content is
  not memory; it becomes memory only through a separate, explicit memory event;
- principal or tenant identity semantics — those are Cycle 015's, re-exported
  here rather than redefined;
- OAuth, OIDC, JWT verification, JWKS, token exchange, identity providers, PDPs,
  remote AuthZEN or MCP auth hardening. Those belong to Cycle 018.

Blurring any of these would let a retrieval report be read as covering a question
it never asked.

## Before you open a pull request

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
python scripts/gen-rag-security-corpus.py --check
python scripts/gen-rag-security-scenarios.py --check
python scripts/gen-rag-security-hostile-fixtures.py --check
python scripts/run-ci-job-locally.py .github/workflows/ci.yml rag-security-2026
```

The last command runs the real workflow job rather than an equivalent by hand,
which is the point: a gate that is only ever approximated locally is a gate
nobody has actually run.
