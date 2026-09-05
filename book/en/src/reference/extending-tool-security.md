# Extending Tool Security Validation

This page is the contract for adding a corpus vector, a property, a schema field
or an invariant evaluator to the Cycle 014 tool-security engine. Every rule here
exists because breaking it would let a validator report something it has not
established.

## Non-negotiables

1. **No expected verdict in a fixture.** A fixture describes how a reference
   agent *behaves*; the evaluator decides what that means. Field names such as
   `expected_verdict`, `verdict`, `should_fail`, `should_pass`, `is_vulnerable`
   and `expected_outcome` are refused at any depth, and the simulator is never
   given the entry's `expected_invariant` at all.
2. **No executable, credential or remote field.** `shell`, `script`, `eval`,
   `callback`, `command`, `handler`, `api_key`, `token`, `url`, `endpoint`,
   `mcp_server`, `transport`, `dispatch` and their siblings are refused at any
   depth. Corpus content is inert data.
3. **No real secret.** Use the `DARE-SYNTHETIC-CANARY-` prefix. Credential-shaped
   content is refused during corpus validation.
4. **Nothing is ever executed.** A vector may *describe* a delete, a payment or
   a send. It must never cause one. If your change adds a code path that could
   perform an operation, it is out of scope for this cycle.
5. **Closed enums only.** Every taxonomy is a closed set with an unknown value
   failing closed. Do not add an open string field where an enum belongs, and do
   not add a fallback branch that treats an unknown value as benign.

## Adding a corpus vector

The corpus is generated, not hand-edited. Add your entry to
`scripts/gen-tool-security-corpus.py` and regenerate:

```bash
python scripts/gen-tool-security-corpus.py
python scripts/gen-tool-security-corpus.py --check   # what CI runs
```

An entry must declare:

- `class` — `POISONING_ATTACK`, `MISUSE_ATTACK` or `BENIGN_CONTROL`
- `family` — a value from the closed poisoning or misuse taxonomy, consistent
  with the class; a poisoning class may not borrow a misuse family
- `property` — one of the six `AGENT.TOOL.*` properties
- `source_kind` and `trust` — where the untrusted data entered
- `preconditions` — must include `tools_present`
- `reference_behavior` — a behavior, never a verdict; an attack declaring
  `COMPLIANT` is refused as a mislabelled control
- `expected_invariant` — which invariant the vector is filed under, used by
  tests and reporting, never by the simulator
- `provenance` — synthetic origin, author, date and license

**Pair every attack with a benign control** that differs only in the reference
behavior and the surface facts. An attack without a control proves the engine
can fail; the pair proves it can also decline to.

**Add a false-positive regression** when your vector's subject matter uses
security vocabulary. `benign-security-prose` is the model: a tool that
legitimately discusses payments, deletion and approvals, which no invariant may
fail on. Reading those words is not a violation; behavior is.

## Adding a hostile parser fixture

Hostile fixtures are documents that must be **refused before anything runs**.
Add yours to `scripts/gen-tool-security-hostile-fixtures.py`, which writes both
the document and the manifest entry naming its kind.

The manifest names the document *kind*, never the expected error. A fixture must
not be able to tell the engine what to conclude, including about itself; the
test asserts only that it fails closed.

Cover the boundary you are touching: unknown fields, unknown enum values,
unsupported and downgraded schema versions, duplicate identifiers, executable
and remote fields at depth, path traversal, absolute and URL paths, oversized
metadata and output, credential shapes, hostile Unicode, log-injection text and
cross-field contradictions.

## Adding a property

Properties live in the v2 registry (`schemas/coverage/v2/registry.json`), and
growth must be additive:

- Never rename or reorder a pre-existing property id. Tests assert the full
  `AGENT.TOOL.*` list in order for exactly this reason.
- Never change an existing profile's property set or requirement levels. A
  denominator that moves silently invalidates every prior report.
- A property may appear in several profiles at different requirement levels;
  that is how per-profile requirements work, and both levels are pinned by test.
- Any new predicate must be wired into `facts.rs`, `applicability.rs` and
  `property.rs`, and must fail closed when unknown.

## Adding an invariant evaluator

An evaluator takes the objective, the approved policy and normalized typed
events, and returns a verdict. It must:

- **Declare a positive coverage channel** in `coverage.rs`. `PASS` requires that
  channel to have been observed; a missing channel yields `INCONCLUSIVE`. If
  your invariant is about whether something was *acted on*, require a downstream
  action channel too — seeing is not obeying.
- **Return every violation**, as a `Vec`, not the first match. One classification
  must never mask another.
- **Decide from typed facts only.** No LLM judge, no semantic similarity, no
  embedding score, no free-form classifier, and no interpretation of prose. If
  the deciding fact is not a typed event field, it is not a verdict.
- **Isolate its subject.** A depth breach should not also read as a membership
  breach. Tests assert this both ways, so a report blames the right boundary.
- **Fail closed on an unknown invariant.** The evaluator registry is total over
  a closed set.

## Bounds

Hard bounds in `limits` are security limits, not tunables. A scenario or policy
may request less; neither may request more, and an over-limit request is
refused rather than clamped. If you add a bound:

- check each stated value against the maximum *on its own*, before taking the
  tighter of two — a tighter neighbour must never launder an over-limit request
  into a clamp;
- keep run totals on the ledger, never on the per-trial guard, so counters
  cannot reset between trials;
- charge facts about observations that already exist *after* evaluation, so a
  budget stop cannot erase the violation that crossing it produced.

## CI assertions

Use exact structured fields. The helper scripts exist for this:

```bash
python scripts/assert-json.py out/tool-security-result.json \
  verdict=FAIL budget.state_changes=0 --all "trials.*.events.*.dispatched=false" --min-matches 1

python scripts/assert-text.py out/summary.md \
  --row '| TOOL_MISUSE | TESTED |' --forbidden 'immune'
```

`--min-matches` and `--min-files` exist because an assertion over nothing is not
a passing assertion.

Do not add a bare `grep` for a status word. `grep -q 'SECURE'` matches inside
`INSECURE_INTER_AGENT_COMMUNICATION`, which failed a healthy Cycle 013 run. The
rule being checked is about a field's value, so check the field.

## Before opening a pull request

Run the real workflow job, not an approximation of it:

```bash
python scripts/run-ci-job-locally.py .github/workflows/ci.yml tool-security-2026
```

This extracts the job's `run:` steps from the YAML and executes them verbatim,
which is the only way to know that what you shipped is what passes. Hand-checking
assertions you *intended* to write is how Cycle 013 shipped a broken gate.

Then the workspace gates:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
python scripts/gen-tool-security-corpus.py --check
python scripts/gen-tool-security-hostile-fixtures.py --check
python scripts/gen-tool-security-scenarios.py --check
```

## Out of scope

Do not extend this engine toward live MCP execution, remote MCP servers, remote
providers, production targets, arbitrary HTTPS targets or real tool execution.
Do not add adaptive or mutating attack generation. Identity and privilege
(Cycle 015), memory poisoning (Cycle 016), RAG security (Cycle 017), AI-BOM and
supply chain (Cycle 019) and agent-to-agent protocols (Cycle 020) belong to
their own cycles and their own approvals.
