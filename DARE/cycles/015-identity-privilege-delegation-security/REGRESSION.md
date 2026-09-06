# Cycle 015 — Regression Record

Every result below was produced by running the stated command on this machine at
the stated commit. Nothing here is recorded as passing because it was expected
to; anything not executed is marked as such.

## Environment

| Field | Value |
|---|---|
| Head SHA at execution | `06c0ad0ff602dccad728bd48661ef760603846b8` |
| Gates re-run at | `562e6a0a31c349b86409350802d3530800f61e78` |
| Branch | `agent/cycle-015-identity-privilege-delegation-security` |
| Baseline | `main @ 2f9c02b4f4f94daa5478a0785f74814fb2d021a2` |
| Toolchain | `rustc 1.94.1 (e408947bf 2026-03-25)` |
| Cargo | `cargo 1.94.1 (29ea6fb6a 2026-03-24)` |
| Platform | Windows 11 (x86_64-pc-windows-msvc) |
| Local CI shell | Git Bash (`C:\Program Files\Git\bin\bash.exe`) |
| Date | 2026-09-05 |

Two commits after the measured head touch code-adjacent files: `f207cff` adds
the new workspace member to `Cargo.lock`, and `562e6a0` restores the v2
registry's shipped compact formatting so its diff reads as the four added
properties it is. Neither changes behaviour or schema content — the registry
parses to the identical set of 30 properties either way — and every gate below
was re-run at `562e6a0`.

The commits that follow it are this file and `PROOF.md`, which change no code,
schema, fixture or workflow. A record cannot name its own commit; `562e6a0` is
the last head at which the gates were measured.

## Workspace gates

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --all --check` | **PASS** — exit 0, no diff |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | **PASS** — exit 0, 0 warnings, 0 errors |
| Tests | `cargo test --workspace` | **PASS** — exit 0, **1716 passing, 0 failing**, 123 test binaries |
| Audit | `cargo audit` | **PASS** — exit 0, 0 vulnerabilities, 1 allowed warning (see below) |

Baseline was 1315 passing tests at `main @ 2f9c02b`. Cycle 015 adds **401**.

### `cargo audit` warning

One allowed warning, pre-existing and not introduced by this cycle:

```
Crate:   chacha20
Warning: yanked
```

It arrives transitively through `dare-mcp-discovery -> reqwest -> quinn ->
quinn-proto -> chacha20`. It is a yank notice, not a vulnerability advisory, and
no CVE is reported. `dare-identity-security` depends on no transport, HTTP,
OAuth or token-parsing crate, so nothing added in Cycle 015 contributes to it.

## Cycle 015 test suites

Each run individually with `cargo test <spec>`.

| Suite | Command | Passing |
|---|---|---|
| Engine unit tests | `cargo test -p dare-identity-security --lib` | 252 |
| Deterministic invariants | `cargo test -p dare-identity-security --test deterministic_invariants` | 36 |
| The 24 IDENTITY-LAB fixtures | `cargo test -p dare-identity-security --test lab_scenarios` | 9 |
| Corpus, pairs and controls | `cargo test -p dare-identity-security --test corpus_integration` | 9 |
| Hostile parser fixtures | `cargo test -p dare-identity-security --test hostile_fixtures` | 7 |
| Multi-violation and redaction hygiene | `cargo test -p dare-identity-security --test violations_and_hygiene` | 10 |
| Profile and coverage integration | `cargo test -p dare-coverage --test identity_security_profile` | 9 |
| Properties and additive growth | `cargo test -p dare-coverage --test identity_security_properties` | 14 |
| Standards provenance | `cargo test -p dare-coverage --lib identity_security_standards` | 19 |
| Product metadata and bounded claims | `cargo test -p dare-product --lib identity_security_metadata` | 9 |
| CLI flag surface | `cargo test -p dare-agent-security --lib identity_security` | 8 |
| CLI end to end | `cargo test -p dare-agent-security --test identity_security_cli` | 11 |
| Product reporting bridge | `cargo test -p dare-agent-security --test identity_security_product` | 8 |

Total attributable to Cycle 015: **401** across engine, coverage, product and
CLI layers.

## Compatibility regressions

Each run individually. Every one is green at this head.

| Regression | Command | Result |
|---|---|---|
| Cycle 003 authorization integrity | `cargo test -p dare-coaz-integrity` | **PASS** — 124 passing |
| Cycle 013 prompt injection | `cargo test -p dare-prompt-injection` | **PASS** — 271 passing |
| Cycle 014 tool security | `cargo test -p dare-tool-security` | **PASS** — 276 passing |
| Coverage engine (all cycles) | `cargo test -p dare-coverage` | **PASS** — 144 passing |
| Cycle 001 evidence kernel | `cargo test -p dare-security-evidence` | **PASS** — 75 passing |
| Cycle 009 adversarial substrate | `cargo test -p dare-adversarial` | **PASS** — 14 passing |

Per-crate counts for Cycles 003, 013 and 014 are **unchanged** from the Cycle 014
baseline (124 / 271 / 276), which is the intended result: Cycle 015 added
alongside them and altered none of them.

The `identity-security-2026` CI job additionally re-runs, end to end:

- the Cycle 003 `validate coaz-integrity --all` gate;
- a Cycle 014 `validate tool-security` run against `TOOL-LAB-001`;
- a Cycle 013 `validate prompt-injection` run against `PI-LAB-001`;
- the Cycle 012 Agentic baseline coverage run plus
  `assert-risk-family-state.py`, which is what pins that no untested risk family
  renders as `SECURE`;
- the MCP baseline coverage run, including the assertion that it writes **no**
  risk-family artifact.

All of those passed as part of the local workflow-job run recorded below.

## Documentation builds

| Book | Command | Result |
|---|---|---|
| English | `mdbook build book/en` | **PASS** — exit 0 |
| Portuguese | `mdbook build book/pt` | **PASS** — exit 0 |

The Portuguese book carries no Cycle 013, 014 or 015 concept page; Cycle 015
follows the same precedent rather than introducing a partial translation.

## The actual CI job, run locally

```
python scripts/run-ci-job-locally.py .github/workflows/ci.yml identity-security-2026
```

**PASS — all 36 steps.** This executes the job exactly as written in
`.github/workflows/ci.yml`; the commands were not reproduced by hand as a
substitute. Full step list, in order:

```
[PASS] Engine unit tests (schemas, enums, invariants, bounds, adapters)
[PASS] Deterministic invariant evaluation across PASS, FAIL and INCONCLUSIVE
[PASS] The 24 IDENTITY-LAB fixtures end to end
[PASS] Corpus, paired vectors and benign controls
[PASS] Hostile parser fixtures fail closed
[PASS] Independent multi-violation capture and redaction hygiene
[PASS] Identity-security profile and coverage integration
[PASS] Identity-security properties and standards provenance
[PASS] Additive product metadata and bounded-claim wording
[PASS] CLI flag surface (no provider, credential, PDP or live-identity flag)
[PASS] CLI end-to-end matrix and product reporting bridge
[PASS] Corpus, scenarios and hostile fixtures are generated, not hand-edited
[PASS] Offline CLI - the initiating principal is preserved
[PASS] Offline CLI - agent authority substituted for the user fails
[PASS] Offline CLI - delegated scope excess fails
[PASS] A cross-tenant intent is proven from declarations, never by access
[PASS] Credential availability is not delegated authority
[PASS] A permit does not survive an authorization-relevant mutation
[PASS] A denied operation is reported and never dispatched
[PASS] Absence of evidence is INCONCLUSIVE, never PASS and never FAIL
[PASS] Independent violations are all recorded, never masked
[PASS] Replay reads only a local trace and stays offline
[PASS] An unresolvable or over-bound scenario is refused before evaluation
[PASS] Trial hard maximum is enforced and never clamped upward
[PASS] Provider, credential, PDP and live-identity flags do not exist
[PASS] No live identity mode can be selected
[PASS] Report wording carries no universal identity-security claim
[PASS] The approved bounded wording is used verbatim on a pass
[PASS] Summaries report each surface separately and name untested ones
[PASS] No artifact leaks a canary, credential or provider
[PASS] Authorization-integrity regression (Cycle 003)
[PASS] Tool Security regression (Cycle 014)
[PASS] Prompt Injection regression (Cycle 013)
[PASS] Agentic baseline regression (Cycle 012)
[PASS] No untested risk family renders as SECURE
[PASS] MCP baseline regression
```

### Workflow trigger

`ci.yml` still declares exactly:

```yaml
on:
  pull_request:
    branches: [main]
    types: [opened]
```

No `push:` trigger was added. The workflow now has 13 jobs (12 before), the new
one being `identity-security-2026`.

## Additive movement against the frozen baseline

Predicted in `BASELINE.md` §11 and confirmed here:

| Measure | Before | After |
|---|---|---|
| Workspace tests | 1315 | 1716 |
| v2 registry properties | 26 | 30 |
| Assessment profiles | 4 | 5 |
| Workspace crates | 13 | 14 |
| CLI `validate` subcommands | 8 | 9 |
| CI jobs | 12 | 13 |
| v2 applicability predicates | 24 | 28 |
| v2 property categories | 19 | 22 |

New artifacts: 10 schemas under `schemas/identity-security/v1/`, 32 corpus
entries plus 62 adversarial parser fixtures under
`corpus/identity-security/v1/`, 24 IDENTITY-LAB scenario fixtures, 1 replay
trace, and 3 generator scripts.

Nothing was renamed, removed or re-scoped. `AGENT.IDENTITY.DELEGATION_INTEGRITY`
and `AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION` keep their identifiers and meaning,
no earlier profile's requirement levels changed, and `dare-coverage/src/math.rs`
— which owns denominator semantics — was not edited.

## Defects found and fixed during execution

These were found by tests written during the cycle, not by review afterwards.
Each is recorded with what was wrong and why it mattered.

1. **The credential sweep matched vocabulary, not shape.** The literal prefix
   `"bearer "` fired on the honest sentence *"without any bearer material"*,
   which made a truthful description of the boundary unwritable. Fixed by
   requiring a token-shaped value of at least 16 characters
   (`contains_bearer_credential`), matching the Cycle 013 and 014 redaction
   discipline. Regression:
   `a_bearer_credential_is_refused_but_the_word_bearer_is_not`. A check that
   fires on ordinary prose is a check people switch off.

2. **PEM masking stopped at the first whitespace.** `-----BEGIN PRIVATE KEY-----
   MIIEvQ...` had its armour masked and its key body left in the retained text,
   because key material is whitespace-separated base64 across several lines.
   Fixed by masking the whole armoured block, through the closing armour or to
   the end of the value when the block is unterminated. Regression:
   `an_armoured_key_block_is_masked_whole_and_not_just_its_header`.

3. **Corpus values were never swept for control characters.** A newline in a
   corpus title could forge a log line and a bidi override could make two
   identifiers render identically. Fixed by `assert_no_hostile_values`, which
   refuses presentation-hostile text in every corpus value; single-line prose
   stays writable. Found by the `log-injection-title` hostile fixture.

4. **A replay trace could carry an orphan permit.** A decision could name an
   operation the trial never observed, which would have carried into evidence as
   covering something nobody could inspect. Now refused at parse time, before a
   scenario is even involved. Found by the `trace-orphan-permit` hostile fixture.

5. **The scenario model carried an expected-verdict-shaped field.**
   `invariant.expected: Option<bool>` was never read by the evaluator, but it
   invited exactly the coupling this cycle forbids. Removed from the schema and
   the model; a scenario carrying it is now refused. Regression:
   `a_scenario_cannot_state_the_verdict_it_wants`.

6. **Two invariants were unreachable in the failing direction.** The coverage
   test found that no lab drove `INITIATING_PRINCIPAL_PRESERVED` or
   `DELEGATION_CHAIN_NO_PRIVILEGE_AMPLIFICATION` to `FAIL`. Fixed at the source
   rather than by relaxing the test: LAB-020 now substitutes both principal
   roles, and LAB-004's over-scope action arises from a handoff that actually
   widened the ceiling. Every invariant is now exercised in both directions.

7. **A kill-switch test asserted nothing.** The local-synthetic adapter compared
   the step's target against its own field, so target substitution was
   impossible by construction and the test's conditional never fired. Fixed by
   making the step name the scenario being observed while the adapter holds the
   one it was approved for, so pointing an approved run at another scenario is a
   real substitution the Cycle 009 control catches. Regression:
   `pointing_an_approved_run_at_another_scenario_trips_the_kill_switch`.

8. **Replay planned more trials than a trace could supply.** A three-trial plan
   against a one-trial trace ended in a harness error that said nothing about
   the boundary under test. The plan is now reduced to what the source can
   supply; `clamped_to_available` is downward-only by construction and can never
   raise a count. Regression:
   `a_plan_can_be_reduced_to_what_a_source_can_supply_but_never_raised`.

## Deviations from the plan

1. **`invariant.expected` removed.** DESIGN did not require this field; it was
   introduced during task-010/013 and removed once its hazard was recognised.
   This narrows the scenario contract rather than widening it, and no consumer
   existed.

2. **`fixtures/identity-security/traces/` added.** The replay CI step needs a
   trace, and DESIGN §19 places the corpus tree but not the trace fixture.
   Traces are generated by the scenario generator and covered by its `--check`.

3. **The corpus ships 32 entries and 62 hostile fixtures**, above the DESIGN
   minimums. The 24 IDENTITY-LAB scenarios are exactly as enumerated.

4. **The Portuguese book was not extended.** Consistent with Cycles 013 and 014,
   which also ship English-only concept and reference pages.

No deviation changes an approved contract, bound, invariant, mode or scope
boundary.

## Residual risks

Carried forward from `BASELINE.md` §13, plus what this cycle adds.

1. **Synthetic reference behavior is not production behavior.** Every
   observation in `SIMULATED` and `LOCAL_SYNTHETIC` mode is staged from a
   fixture. The artifacts mark this (`synthetic: true`) and the report says so,
   but a green run describes a reference agent, not a deployed one.

2. **A finite corpus bounds the claim.** 32 vectors and 24 scenarios exercise
   the twelve invariants in both directions. They do not enumerate the space of
   identity, delegation and authorization failures, and no artifact claims they
   do.

3. **Declarative authority is not cryptographic identity.** Cycle 015 compares
   declared ceilings. It parses no token, verifies no signature, and contacts no
   issuer. A system whose real authority differs from what it declares is
   outside what this can see. That belongs to Cycle 018.

4. **The tenant boundary is proven from labels.** A crossing is established by
   comparing declared tenant labels against a declared ceiling. A deployment
   whose real tenancy differs from its declared tenancy would not be caught.
   This is deliberate: proving it otherwise would mean touching real data.

5. **Coverage contracts are per-invariant, not per-deployment.** Satisfying a
   contract means the run observed the channels that invariant needs. It does
   not mean the deployment exposes every channel worth observing.

6. **The local CI runner is not GitHub Actions.** It executes the job's `run:`
   steps in Git Bash on Windows. Step semantics match; the runner image,
   toolchain provisioning and network posture do not. The PR-open run is the
   authoritative one.

7. **New: the adapters are the only observation source.** An identity property
   that no adapter can express is invisible to the engine regardless of how well
   the invariants are written. Extending observation is a design change, and the
   contributor documentation says so.
