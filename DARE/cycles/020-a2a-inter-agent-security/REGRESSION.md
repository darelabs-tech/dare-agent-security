# Cycle 020 — Regressions and Corrections

Every correction made during execution, what caused it, and what now prevents it
from recurring silently.

All of these preserved the approved scope, the fourteen invariants, the
local/offline boundary, the public property identifiers, the PASS semantics and
the cycle-ownership split. None required redesigning an approved security
contract, so none was stopped for Review.

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

## What did not need correcting

The fourteen invariants, their semantics and their design ids. The sixteen
distinctions. The four verification statuses and what each may satisfy. The
public property identifiers, including the two inherited ones. The `AGENT.A2A.*`
namespace, with no top-level `A2A.*` created. The offline boundary, which was
never loosened for any test, fixture or artifact.
