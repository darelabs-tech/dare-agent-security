# Cycle 020 — Regressions and Corrections

Every correction made during execution, what caused it, and what now prevents it
from recurring silently.

All of these preserved the approved scope, the fourteen invariants, the
local/offline boundary, the public property identifiers, the PASS semantics and
the cycle-ownership split. None required redesigning an approved security
contract, so none was stopped for Review.

Section 13 was found **after this cycle merged**, by post-merge security review.
It is remediation rather than approved scope, and is recorded in full in
`HOTFIX.md` and `EXECUTION/hotfix-001.md`. The 57/57 task count is unchanged.

---

## 1. A word-ban refused the document's own denial — three times

**The pattern.** A check written as "this text must not contain phrase X" fails
against text that *denies* X, because a denial contains the phrase. It happened
three times in this cycle, in three unrelated places, and it is the single most
repeated defect here.

### 1a. The standards record

`the_record_carries_no_credential_or_reachable_target` banned the words "bearer
token". `provenance.json` carries a rule stating the engine never presents a
bearer token, so the record failed its own check.

**Correction.** `contains_bearer_credential` is anchored on **shape**: the
literal `bearer ` followed by at least sixteen credential characters. An honest
sentence about bearer tokens stays writable; a real value is refused.

### 1b. The staged bundle

`the_staged_bundle_carries_no_expected_outcome` banned the bare word `expected`.
The policy's own `expected_audience` and `expected_provider` fields matched —
those are **approvals**, not outcomes.

**Correction.** Narrowed to verdict-shaped names: `expected_verdict`,
`expected_findings`, `expected_outcome`, `"verdict"`, `should_fail`,
`is_secure`.

### 1c. The operator summary

`the_summary_never_claims_more_than_the_run_established` banned "agent is
secure". The summary's own disclaimer — *"not a statement that a remote agent is
secure"* — contains it.

**Correction.** `assert_summary_is_bounded` looks back sixty characters from each
occurrence for a negation (`not `, `never `, `rather than `, `does not `,
`cannot `) and skips the occurrence if it finds one.
`the_summary_gate_refuses_a_claim_and_permits_its_denial` pins both directions
with four cases.

**Why this matters beyond the three instances.** A gate that cannot let a
document deny something forces the document to stop denying it. Every one of
these three would have been "fixed" by deleting the sentence that made the
document honest.

### 1d. A related instance in the taxonomy test

`a_reference_behaviour_is_a_behaviour_and_never_a_verdict` asserted no behaviour
name contains `FAIL`. `HARNESS_FAILURE` does. **Correction:** whole-word
comparison after splitting on `_`.

---

## 2. Two wire formats disagreed with their own prose

`TransportKind::as_str()` returned `JSONRPC`, which is what A2A 1.0.0 documents
carry. serde's `SCREAMING_SNAKE_CASE` derive produced `JSON_RPC`.
`SecuritySchemeKind` was worse: `O_AUTH2_CLIENT_CREDENTIALS`,
`O_AUTH2_AUTHORIZATION_CODE` and `OPEN_ID_CONNECT`, none of which any real
document carries.

A document written with either spelling was readable by only half the engine —
reports said one thing and the parser accepted another.

**Correction.** Explicit `#[serde(rename)]` on all four variants, plus
`every_taxonomy_is_spelled_the_same_way_on_the_wire_and_in_prose`, a macro test
covering **nine** closed enums rather than the two that happened to be caught.

---

## 3. A behaviour named for a crossing staged no crossing

`DuplicateNonIdempotentAction` set `is_repeat` and a non-idempotent effect on an
exchange invoking `summarize` — which the base policy **declares idempotent**.
The repeat was genuinely proven safe, so the behaviour staged nothing and the
corpus entry could never fail.

**Correction.** The behaviour now uses `send-invoice`, with a matching skill
grant and card skill so the exchange is otherwise legitimate and only the
idempotency question is open.

---

## 4. Two corpus entries were filed against the wrong answer

Both were found by the harness contract, and in both cases the **fixture** was
corrected rather than the engine.

### 4a. `A2A-LAB-004` — an unsigned card is not a gap

Filed as a `GAP` for I01 on the reasoning that an unrecorded signature
verification is missing evidence. The run reported I01 **PASS**, and the reason
was correct: policy pins `expected_provider`, the provider comparison ran, and
the card's binding to what policy approved was decided without a signature.

The frozen distinction is *signed Agent Card != authorized provider*. It does
not run backwards into *unsigned card == unbound card*.

**Correction.** `A2A-LAB-004` is now a `CONTROL` — an unsigned card whose binding
the pinned provider already settles. A new entry `A2A-LAB-004B` carries the real
I01 gap: a card policy says nothing about, where nothing was compared to
anything.

### 4b. `A2A-LAB-011` — a different principal is not a mismatch

Filed as an `ATTACK` on I02. `PeerIdentityMismatch` stages a peer authenticating
as `svc-somebody-else` **with the authentication record agreeing**, so nothing
mismatches: I02 asks about audience, provider and authentication status, and all
three hold.

What the bundle actually crosses is I05 — a service principal with no delegated
subject invoking a skill granted only to `user-alice`.

**Correction.** The entry moved to I05, where it stages the distinction
*successful authentication != skill authorization* from the direction where
there is no delegated subject at all.

---

## 5. The profile denominator test proved nothing, then proved the wrong thing

Two defects in one test, both found before it could pass for a bad reason.

**First:** it computed each earlier profile's expected property count by calling
the same accessor it then checked. Comparing a profile against itself passes no
matter what moves. **Correction:** the counts are literals.

**Second:** it asserted no earlier profile contains any `AGENT.A2A.*` property.
That is false — the Cycle 012 `agentic-security-baseline-2026` has selected
`AGENT.A2A.MESSAGE_AUTHENTICITY` since that cycle, and inheriting it is the
point.

**Correction.** Split in two. `no_earlier_profile_denominator_moved` pins nine
literal counts. `this_cycles_ten_new_properties_reached_no_earlier_profile`
names the ten properties this cycle *created* and asserts none appears in any
earlier profile, plus that the Cycle 012 baseline still selects exactly the one
inherited property.

That is the real risk: a new property leaking into an older profile would change
that profile's denominator without changing its file, and every assessment
already filed against it would silently mean something different.

---

## 6. The registry edit broke the schema before it broke a test

Appending ten properties to `schemas/coverage/v2/registry.json` failed six
existing coverage tests with `"peer_authentication_evidence_present" is not one
of ...`. The predicate enum in `property.schema.json` had not been extended.

**Correction.** Enum extended 46 -> 57. The failure was loud and immediate, which
is the behaviour a closed enum exists to produce.

---

## 7. Corrections carried in from earlier cycles rather than rediscovered

Recorded because they are places this cycle would otherwise have repeated a
known defect. None of these was a failure in Cycle 020 — each is a defect from
an earlier cycle that was designed out from the start.

| Carried from | What it would have been |
|---|---|
| Cycle 019 | the output artifact exempt from its own budget — `admit_output` and `serialize_result_with_final_budget` charge it |
| Cycle 019 | `violations` skipped when empty, breaking `--count violations=0` — always serialized |
| Cycle 019 | a compliant run reporting INCONCLUSIVE — `applicable` distinguishes "no subject" from "undecided" |
| Cycle 019 | coverage satisfied by a present-but-uncomparable channel — `comparison_reason` is a second step |
| Cycle 019 | the credential sweep failing open after the first `#[cfg(test)]` — `shipping_lines` is brace-aware from the start |
| Cycle 018 | a credential list written uppercase and matched lowercase — `CREDENTIAL_SHAPED_VALUES` is all-lowercase, with a comment saying why |
| Cycle 018 | FAIL hidden behind INCONCLUSIVE — precedence asserted in `one_concrete_failure_outranks_every_undecided_answer` |
| Cycle 016 / 018 / 019 | PROOF.md citing tests that do not exist — `scripts/k20/verify_proof_citations.py` is a gate |
| Cycle 013 | substring gates in CI — every assertion in `a2a-security-2026` is parsed structure |

The Cycle 013 one deserves emphasis: `SECURE` matches inside
`INSECURE_INTER_AGENT_COMMUNICATION`, and that string **is this cycle's risk
family**. A substring gate here would have reproduced the exact original defect
under the exact original name.

---

## 8. Mechanical corrections

Recorded for completeness; none changed a security contract.

- clippy `unnecessary_lazy_evaluations` -> `.then_some()`
- clippy `needless_lifetimes` on `fn a2a<'a>(...)` and `fn outcome_for<'a>(...)`
- clippy `bool_assert_comparison` -> `assert!`
- clippy `type_complexity` in a delegation test -> a `type Mutation` alias
- `serde_json::to_string` over a `[T; 37]` — arrays above 32 are not `Serialize`
  -> `.to_vec()`
- a test naming `dare_coverage::SchemaRef` and `PlannedProperty.status`, neither
  of which exists -> rewritten against `evaluate_applicability`
- `property.risk_family` is `Option<RiskFamily>` with no `as_str` -> compared via
  `serde_json::to_value`
- `dare_security_evidence::verdict` is a private module -> `dare_security_evidence::Verdict`
- `ReferenceBehavior` has no `as_str` -> `{behavior:?}` in test messages
- removing a throwaway decode probe left unbalanced braces in
  `local_synthetic.rs` -> repaired
- unused imports left after narrowing two tests' import lists
- a `let peers = ...` chain needing an explicit `Vec<PeerRecord>` annotation

---

## 9. One expectation corrected against the engine's answer, not the reverse

While writing the CI job, `A2A-LAB-033` (`TenantClaimUnverified`, classified
`GAP` for I09) was expected to aggregate to INCONCLUSIVE. It aggregates to
**FAIL**.

The engine is right. `user-unknown` is a subject policy knows nothing about, so
I09 is correctly undecided — *and* that same subject holds no grant for
`summarize`, so I05 correctly reports a violation. A concrete failure outranks an
undecided answer, which is Cycle 018's precedence working as specified.

The GAP contract in the harness is about the entry's **primary** invariant never
reaching an applicable PASS, and it holds. `A2A-LAB-018` and `A2A-LAB-004B` were
used for the CI INCONCLUSIVE steps instead, where the aggregate really is
undecided.

No code changed. The expectation did.

---

## 10. The workspace gate passed here and failed on CI's newer clippy

`cargo clippy --workspace --all-targets -- -D warnings` was clean locally on
clippy 0.1.94 and failed the `Rust workspace` job on the stable toolchain CI
installs (1.98), which flags a shape the older lint let through:

```text
error: this `if` can be collapsed into the outer `match`
  --> crates/dare-a2a-security/src/invariant.rs:456:17
```

`peer_identity` matched `A2aObservation::PeerAuthenticationContext(context)` and
then tested `context.status.is_concrete_failure()` inside the arm. It is now a
match guard, with the non-failing case falling through to the wildcard that
already followed it. Because that arm sits immediately before `_ => {}`, the
guard changes the outcome for no observation: an authentication that was not
checked and found invalid raised no violation before and raises none now.

The correction had been written into the working tree but never committed, so
the head CI actually tested still carried the failure. A local gate is only as
strong as the toolchain that runs it.

Evidence: `cargo clippy --workspace --all-targets -- -D warnings` clean;
`cargo test -p dare-a2a-security --lib` 300 passed.

---

## 11. A lab trace file could be read while it was empty

`cargo test --workspace` failed in `dare-agent-security --test e2e_matrix`:

```text
stdio_current_protocol_trace_is_subset_of_allowlist
expected SYNTHETIC_MCP_TRACE_PATH dump at ...
```

Measured rather than assumed: 1 of 10 full-binary runs failed, several passing
runs burned the reader's entire five-second retry budget, and the test passed
every time under `--test-threads=1`. The dump left behind by a failing run was
zero bytes.

The cause is in `labs/synthetic-mcp/src/trace.rs` -- Cycle 002 code this cycle
never touched. `write_trace_file` opened the dump with `truncate(true)` and then
wrote it, so the file existed and was empty for the width of that window. The
discovery adapter sets `kill_on_drop(true)` on the lab process, and a kill
landing inside that window left a permanently empty dump. That is why no amount
of reader retrying recovered it, and why the earlier correction -- widening the
retry budget -- had not fixed it.

The write is now atomic: the body goes to a per-process, per-write sibling file
that is renamed over the target, so the dump is either absent or one complete
snapshot. A first hypothesis -- that same-nanosecond paths collided between
parallel tests -- was tested and falsified before this one was adopted.

Regression: `trace::tests::a_reader_never_observes_a_partial_trace_file` rewrites
the dump on one thread while another reads it, and holds that a successful read
never returns empty or partial JSON. Restoring the truncate-in-place write makes
it fail with `reader observed an empty trace file`; with the fix it passes,
`synthetic-mcp --lib` is 8 passed, and `e2e_matrix` went 15 runs for 15 with no
zero-byte dump left behind.

This is a test-harness durability fix. It touches no invariant, property id,
verdict semantics or the offline boundary.

---

## 12. The canvas outlived its cycle, for the third time

`DARE/.canvas.md` still described Cycle 019 at 53/53 while Cycle 020 ran. The
generator's own docstring records the same drift twice before, which is the
signal that regenerating by hand is not a control.

It is regenerated for Cycle 020 (57/57) and `scripts/regen-canvas.py` grew a
`--check` mode, wired into the docs gate. `--check` compares everything except
the `**Updated:**` stamp, which changes on every run: regenerating and then
running `git diff --exit-code` would have failed on every CI run whether or not
the canvas had drifted. Verified both ways -- a stale timestamp alone passes, a
changed task row fails with a message naming the fix.

---

## 13. Post-merge: a correct predicate that nothing called

Found after Cycle 020 merged, by security review rather than by any gate here.
Recorded in full in `HOTFIX.md`; kept short in this file, which is the cycle's
regression narrative.

Three invariants could report `PASS` without a `VALID` verification behind them:

```text
I02 INDETERMINATE peer authentication          -> PASS (want INCONCLUSIVE)
I03 INDETERMINATE message authentication       -> PASS (want INCONCLUSIVE)
I04 INDETERMINATE peer authentication          -> PASS (want INCONCLUSIVE)
I03 a covered envelope rescuing an uncertain verifier
I04 a VALID verification for a *different* scheme satisfying the requirement
aggregation reporting PASS with I03 undecided
```

The uncomfortable part is where the defect was not. `may_satisfy_positive_evidence`
implements the rule correctly and had a passing test — `only_valid_may_satisfy_positive_evidence_and_only_invalid_is_a_finding`
walks all four statuses and has been green since task-008. The evaluators simply
never called it. I02 asked `is_recorded_evidence()`, which answers "was it
checked?" and is true of `INDETERMINATE`; I03 and I04 asked only whether a
comparison had been *made*, never what it *concluded*.

So this cycle shipped a correct predicate, a passing test for it, and three call
sites that ignored both. A unit test on a predicate proves nothing about the
code that does not consult it — which is why the hotfix's thirty regressions
drive whole invariants and not the predicate.

`Option<bool>` carried a second instance of the same shape. It has three answers
where the identity question has four: "policy pinned nothing" and "policy pinned
a value the evidence never carried" both arrived as `None`, so absence read as
agreement. `BindingCheck` replaced it with four named answers and two explicit
questions — `may_satisfy_positive_evidence()` for optional dimensions,
`is_proven()` for required ones.

Two corrections found while writing the fix, both caught by running things
rather than assuming them:

- the new CI steps first expected CLI exit **1** for a concrete failure; it is
  **2**, confirmed by running a scenario before the assertion was written;
- staging A2A-LAB-063 first gave a peer an API-key verification carrying a
  delegated subject, and admission refused the bundle — correctly, since an API
  key authenticates a service and carries no user. The refusal was right; the
  vector was rewritten to vary the scheme id and hold the kind, which is the
  binding actually under test.

One fixture changed, and it is worth being explicit that it is not the forbidden
kind. `base_policy()` in `simulated.rs` gained `expected_logical_agent` and
`requires_delegated_identity` — evidence the strengthened contract now requires.
No expectation, classification or verdict moved anywhere in the corpus, and
`corpus.rs` needed no edit for the existing 59 vectors to keep passing. The
corpus was already right; the evaluator was not.

---

## What did not need correcting

The fourteen invariants, their semantics and their design ids. The sixteen
distinctions. The four verification statuses and what each may satisfy. The
public property identifiers, including the two inherited ones. The `AGENT.A2A.*`
namespace, with no top-level `A2A.*` created. The offline boundary, which was
never loosened for any test, fixture or artifact.
