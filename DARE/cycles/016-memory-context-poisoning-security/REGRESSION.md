# Cycle 016 — Regression Record

**Cycle:** 016 — Memory and Context Poisoning Security
**Branch:** `agent/cycle-016-memory-context-poisoning-security`
**Baseline:** `main @ 9d543ae0ec202b7ad05a852179ca5703857a317a`
**Head at which every gate below was executed:** `8e6be106a14d672eef1eb0749f65e0543484e1c8`

This record names a head rather than its own commit, because a record cannot
contain the hash of the commit that introduces it. `8e6be10` is the last head at
which fmt, clippy, the full workspace suite, `cargo audit`, both book builds and
the 39-step `memory-security-2026` job were all executed.

---

## 1. Gates executed

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --all --check` | clean |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | 0 errors, 0 warnings |
| Tests | `cargo test --workspace` | **2067 passed, 0 failed** across 133 test binaries |
| Audit | `cargo audit` | 0 vulnerabilities; 1 pre-existing allowed warning (unmaintained transitive dependency of `reqwest`, inherited and unchanged) |
| Documentation | `mdbook build book/en` | built |
| Documentation | `mdbook build book/pt` | built |
| Cycle gate | `python scripts/run-ci-job-locally.py .github/workflows/ci.yml memory-security-2026` | **all 39 steps PASSED** |

The last command runs the real job parsed out of `.github/workflows/ci.yml`, not
a hand-written equivalent. That distinction is the point of the requirement: a
gate only ever approximated locally is a gate nobody has actually run.

---

## 2. Test movement against the frozen baseline

| Crate | Baseline (Cycle 015) | Head | Delta |
|---|---:|---:|---:|
| `dare-security-evidence` | 75 | 75 | 0 |
| `dare-coaz-integrity` | 124 | 124 | 0 |
| `dare-coverage` | 144 | 186 | +42 |
| `dare-adversarial` | 14 | 14 | 0 |
| `dare-prompt-injection` | 271 | 271 | 0 |
| `dare-tool-security` | 276 | 276 | 0 |
| `dare-identity-security` | 323 | 323 | 0 |
| `dare-memory-security` | — | 265 | +265 |
| `dare-product` | 59 | 69 | +10 |
| `dare-agent-security` (CLI) | 194 | 235 | +41 |
| **Workspace total** | **1716** | **2067** | **+351** |

Every crate that predates this cycle holds its count exactly, except the three
that were extended additively. Nothing was removed, weakened or renamed to make
a number move.

---

## 3. Structural movement

| Measure | Baseline | Head | Note |
|---|---:|---:|---|
| v2 registry properties | 30 | 34 | four additive `AGENT.MEMORY.*` properties |
| v2 applicability predicates | 28 | 32 | four additive memory predicates |
| v2 property categories | 22 | 22 | unchanged |
| Assessment profiles | 5 | 6 | `memory-security-baseline-2026` added |
| Workspace crates | 14 | 15 | `dare-memory-security` added |
| CLI subcommands | 9 | 10 | `validate memory-security` added |
| CI jobs | 13 | 14 | `memory-security-2026` added |
| Memory-security schemas | — | 8 | item, store, policy, context, scenario, trace, corpus-entry, corpus-registry |
| Corpus vectors | — | 24 | 15 attacks, 9 controls, five surfaces |
| Lab scenarios | — | 24 | MEMORY-LAB-001…024 |
| Adversarial fixtures | — | 80 | plus a manifest |

The two properties that predate this cycle —
`AGENT.MEMORY.CONTEXT_INTEGRITY` and `AGENT.MEMORY.TENANT_BOUNDARY` — keep their
identifiers, descriptions, applicability predicates, evidence classes and
standards attributions, pinned field by field in
`crates/dare-coverage/tests/memory_security_profile.rs`. No earlier profile's
property count moved, and no property is selected by two profiles.

---

## 4. Defects found and fixed during execution

These were found by tests written for this cycle, not by review afterwards.
Each is recorded with what was actually wrong, because a list of fixes with no
causes is not evidence of anything.

**1. A refusal echoed the remote target it refused.**
The corpus registry validated its schema before sweeping paths, and a JSON
Schema validator reports a failure by quoting the value that failed — so
refusing a URL-shaped corpus path printed the endpoint back into the log line
the refusal exists to prevent. Paths are now swept before the schema runs, and
the refusal names the entry id and the shape of the problem rather than the
value. Caught by `a_refusal_never_echoes_a_remote_target`.

**2. A replayed run reported itself as non-synthetic.**
The result's `synthetic` field came from the mode, and `REPLAY` is not a staged
mode — accurate in the narrow sense and misleading in the one that matters,
since every trace Cycle 016 will admit is required to declare itself synthetic.
A replayed run could therefore have been read as production evidence. The
adapter now answers from the trace it loaded. Caught by the end-to-end CLI
suite.

**3. Two tests passed while proving nothing.**
`result.rs` and `evidence_bridge.rs` staged a trust promotion while judging the
provenance invariant. The runs passed, and they established nothing about either
question. Behaviors are now paired with the invariant they actually bear on.

**4. A trace could assert a binding fact it has no standing to know.**
The trace schema described recall results as carrying full item records, which
would have let a trace claim a cross-tenant item belonged to the acting tenant.
A result now names memory by id and the store supplies the binding facts during
normalization. The schema also allowed a trace to state whether an action was
performed; it now cannot say either way.

**5. The policy dimension schema rejected every dimension.**
`additionalProperties: false` with no outer `properties` block. Rewritten with
an `allOf`/`if`/`then` requiring `values` only for `ONLY`.

**6. A staged canary tripped the redaction gate.**
`populate_protected_field` staged the raw canary as the observed value, which
the redaction gate correctly refused. The staged value now names the memory it
came from, which proves the same thing without carrying protected material.

**7. `assert_safe_identifier` admitted newlines.**
It delegated to the hostile-text check, which tolerates line breaks in free-form
prose. An identifier is not prose; an explicit single-line check was added.

**8. A CI assertion of mine was wrong, and the engine was right.**
I asserted `budget.recall_item_bound=8`, the hard maximum, but MEMORY-LAB-001
asks for at most 4 and the plan correctly honours the narrower of the two. The
assertion now pins 4, with the rule stated where it is checked: a scenario may
always narrow a bound, and nothing can widen one.

**9. A no-op loop in the coverage contract.**
`coverage_contract` iterated the exercise channels and `continue`d in every
branch. Removed, and replaced with a test asserting that naming an invariant as
exercise-requiring matches its actual contract.

**10. A disclaimer could not be written.**
The standards validator refused the honest sentence "not because the engine
implements or is certified against any specification", because it checked only
the immediately preceding word for a negation. It now scans to the start of the
sentence, with a test that a denial in one sentence cannot launder a claim in
the next.

---

## 5. Safety boundary, as executed

Every claim below is asserted by a test or a CI step, not by inspection.

- **No store is reachable.** The crate declares no database driver, HTTP client
  or vector-store SDK. `HarnessMode` has three variants and no remote one.
- **No flag could reach one.** `--url`, `--redis`, `--postgres`, `--vector-db`,
  `--pinecone`, `--qdrant`, `--weaviate`, `--provider`, `--token`, `--api-key`,
  `--remote`, `--command`, `--endpoint` and `--connection-string` are each
  asserted to be rejected by the parser, in the unit suite and again in CI.
- **No mode could name one.** `live`, `remote`, `production`, `http`, `redis`,
  `vector` and `store` are each asserted to be unselectable.
- **Nothing is written and nothing leaves.** Every result records
  `state_changes: 0` and `external_egress_bytes: 0`, and every summary prints
  `Memory items written | 0`.
- **No artifact carries protected material.** All Cycle 016 artifacts are swept
  for canaries, `sk-live-`, PEM headers, bearer credentials, `redis://`,
  `postgresql://` and `example.invalid`.
- **Verdicts do not depend on the clock.** Lifecycle is evaluated at the logical
  time each scenario declares.

---

## 6. Residual risks

Recorded because they are real, not to be discharged by being listed.

1. **The corpus is finite.** 24 vectors and 24 labs across five surfaces. A
   memory-poisoning technique nobody wrote a vector for produces no finding, and
   the report says so rather than implying coverage it does not have.
2. **The reference agent is a simulation.** Observations are staged from
   declarations or replayed from synthetic traces. They describe a reference
   agent, never a production one, and every artifact marks itself synthetic.
3. **Retrieval is entirely unexamined.** RAG, embedding similarity, vector-store
   authorization and document-level isolation are Cycle 017. A clean Cycle 016
   result says nothing about what a retriever will hand an agent.
4. **Protocol and cryptographic identity are unexamined.** No token is parsed or
   verified; authority is modelled declaratively. That is Cycle 018.
5. **The trust ceiling is a policy model, not a measurement.** The engine checks
   that declared trust stays within a declared ceiling. Whether a real system's
   ceilings are set sensibly is outside what a fixture can establish.
6. **A benign control proves the engine tolerates one specific legitimate
   pattern.** Nine controls is not proof that an engine is free of false
   positives against real memory usage at large.
7. **`cargo audit` reports one allowed warning**, inherited from before this
   cycle: an unmaintained transitive dependency of `reqwest`, reached only by the
   MCP discovery path and not by anything in Cycle 016.

---

## 7. What was not done

- `APPROVAL.md` was not authored or amended by this cycle. It is the Product
  Owner's explicit approval, dated 2026-09-05, of the frozen planning artifacts,
  the 63 acceptance criteria and the 37 tasks; execution began only after it.
  Approval of the *result* — this record, the proof and the pull request — is
  the Product Owner's to give and has not been assumed here.
- No Portuguese translations were added. The `book/pt` tree carries
  translation-pending stubs for every capability page, and Cycles 013, 014 and
  015 are in the same state; adding one page for this cycle alone would have
  been inconsistent rather than helpful.
