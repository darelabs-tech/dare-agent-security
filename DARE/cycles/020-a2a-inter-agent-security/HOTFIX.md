# Cycle 020 — Post-merge security hotfix

**Branch:** `hotfix/cycle-020-a2a-security-contracts`
**Base:** `main @ ac25ee5` (Cycle 020 merged as PR #41)
**Scope:** correcting the implementation to meet the approved DESIGN. No approved
contract was redesigned, and no invariant semantics were changed.

Cycle 020 originally completed 57/57 tasks. A post-merge security review
identified semantic defects in positive authentication evidence handling. This
hotfix corrects those defects without changing the approved Cycle 020 design.

The historical 57/57 count is left exactly as it was. This work is recorded here
and in `EXECUTION/hotfix-001.md` rather than as new tasks, because it is
remediation of shipped behaviour rather than approved scope.

---

## 1. What was wrong

The DESIGN gives four verification statuses and says only one may contribute to
a positive result:

```text
VALID         -> may contribute to a positive PASS
INVALID       -> concrete evidence of FAIL
INDETERMINATE -> never a positive PASS
UNRECORDED    -> never a positive PASS
missing       -> INCONCLUSIVE
```

The status predicate implementing that rule — `may_satisfy_positive_evidence` —
was correct, and had its own passing test. The defect is that the evaluators and
coverage contracts for I02, I03 and I04 never consulted it. Each asked whether a
comparison had been *made* and not what it *concluded*.

That is worth stating precisely, because it is the reusable lesson: a correct
predicate with a green test proves nothing about the call sites that ignore it.

### I02 — peer identity binding

Positive coverage asked `status.is_recorded_evidence()`, which answers "was it
checked?" and is true of `INDETERMINATE`. An authentication the verifier could
not conclude therefore satisfied coverage and reported `PASS`.

Separately, I02 compared only provider and audience. That answers "did something
authenticate?" rather than the question the invariant exists for: "is the
authenticated party the one we approved for this role?" A peer's own
`logical_agent_id` was carried through and never compared against anything
local, so *the peer said it is X* was effectively accepted as *X*.

### I03 — message authenticity

Positive coverage asked `covers_observed_envelope.is_some()` — that a comparison
had happened. An `INDETERMINATE` verification over the correct envelope satisfied
coverage and reported `PASS`, converting the verifier's uncertainty into the
engine's confidence.

### I04 — security requirement satisfaction

Positive coverage asked:

```rust
satisfies_card_requirement.is_some() || kind_approved_by_policy.is_some()
```

Either comparison merely having been attempted was enough. A card that requires
OAuth plus an exchange that named OAuth satisfied the requirement with no
verification behind either — a declaration reported as a satisfied mechanism.
Nothing tied a verification to the scheme actually used, so a valid verification
for a *different* scheme the same peer offers also passed.

---

## 2. Security impact

Each defect converts an unproven claim into a positive assurance. In the terms
Cycle 020 uses for its own non-claims:

| Path | Reported | Actually established |
|---|---|---|
| I02 on `INDETERMINATE` | identity bound | a verifier declined to conclude |
| I02 with no approved agent | identity bound | the peer named itself |
| I03 on `INDETERMINATE` | message authentic | a signature covering the right bytes, unverified |
| I04 on a declared scheme | requirement satisfied | a card and an exchange agreed on a name |
| I04 on another scheme's record | requirement satisfied | some other mechanism verified |

Aggregation carried the error outward: because every invariant reported `PASS`,
a whole run reported `PASS`. An operator reading that artifact would have been
told the applicable invariants held under the evidence analysed, when the
evidence in question said nothing either way.

No remote capability, credential handling or network boundary is involved. The
offline boundary was never crossed and is unchanged by this hotfix.

---

## 3. What changed

### `BindingCheck` replaces `Option<bool>` on the identity dimensions

`Option<bool>` had three answers where the question has four, and the missing
one is exactly where the false `PASS` got in: "policy pinned nothing" and
"policy pinned a value the evidence never carried" both arrived as `None`, so
absence read as agreement.

```text
NotExpected  policy pinned nothing            -> may satisfy an optional dimension
Unproven     pinned, nothing observed          -> never positive
Matches      compared and equal                -> positive
Differs      compared and different            -> concrete FAIL
```

`may_satisfy_positive_evidence()` covers optional dimensions; `is_proven()`
covers required ones, where a policy that pinned nothing leaves the question
open rather than agreed.

### Policy gained two fields

| Field | Why |
|---|---|
| `expected_logical_agent` | required before I02 may bind: a peer naming its own agent is a claim, not an approval |
| `requires_delegated_identity` | defaults `false`, so legitimate service-to-service authentication is not failed for lacking a user it never carried |

### The three positive contracts

```text
I02  a VALID peer verification, and for every peer:
     logical agent proven, audience and provider not Unproven,
     and a delegated subject where policy requires one

I03  may_satisfy_positive_evidence() AND covers_observed_envelope == Some(true)

I04  a scheme was used, it satisfies a card requirement, its kind is approved
     by policy, and a verification bound to that scheme id concluded VALID
```

### Two new concrete failures, and one binding

- a logical agent differing from the approved one (I02);
- a service principal standing in where policy requires a delegated subject (I02);
- `verification_status` on the I04 context, resolved **by scheme id** rather
  than by peer, so a record for another mechanism yields `None` rather than
  standing in.

### What deliberately did not change

Tenant stays with I09; I02 does not absorb it. I05 keeps skill authorization.
The fourteen invariants, their ids and semantics, the four verification
statuses, the public `AGENT.A2A.*` property ids, FAIL precedence and the
offline boundary are all untouched.

---

## 4. Method

The defects were reproduced before anything was corrected. Commit `8960fe5`
is deliberately red: it states the DESIGN contract and fails against the merged
implementation, so the bugs exist as reproducible evidence rather than as a
description in a commit message.

Six paths reached `PASS` without a `VALID` verification behind them:

```text
I02 INDETERMINATE peer authentication          -> PASS (want INCONCLUSIVE)
I03 INDETERMINATE message authentication       -> PASS (want INCONCLUSIVE)
I04 INDETERMINATE peer authentication          -> PASS (want INCONCLUSIVE)
I03 covered envelope rescues an uncertain verifier
I04 a VALID verification for a different scheme satisfies the requirement
aggregation reports PASS with I03 undecided
```

The new tests were then checked for teeth by mutation rather than trusted:
forcing `binding_established()` to `true` fails four of them, and making
`requirement_established()` ignore the verification status fails six.

---

## 5. Regression tests

`crates/dare-a2a-security/src/positive_evidence.rs` — 30 tests, driving whole
invariants rather than the status predicates, since the predicates were never
what broke.

- every `VerificationStatus::all()` walked against I02, I03 and I04;
- every `BindingCheck::all()` walked exhaustively;
- audience and provider: unobserved leaves identity undecided, differing fails;
- logical agent: unapproved cannot bind, differing fails;
- service-to-service stays passable; a substituted delegate fails;
- I04: no verification, a merely declared scheme, another peer's verification
  and another scheme's verification all stay short of `PASS`;
- FAIL precedence with an undecided invariant and a concrete violation together.

Five A2A-LAB vectors, verified end to end through the CLI:

| Vector | Class | Verdict |
|---|---|---|
| A2A-LAB-059 | GAP | INCONCLUSIVE |
| A2A-LAB-060 | ATTACK | FAIL |
| A2A-LAB-061 | ATTACK | FAIL |
| A2A-LAB-062 | GAP | INCONCLUSIVE |
| A2A-LAB-063 | GAP | INCONCLUSIVE |

No existing vector's classification, expectation or verdict was changed. The
corpus was already right; the evaluator was not.

---

## 6. CI

`a2a-security-2026` goes from 26 to 29 steps:

```text
Only a VALID verification may satisfy I02, I03 or I04
  -> runs the positive_evidence matrix as a typed contract

An uncertain verification is undecided rather than clean
  -> A2A-LAB-059/062/063 exit 2 and parse as INCONCLUSIVE, zero violations

An identity nobody approved is a finding, not a gap
  -> A2A-LAB-060/061 parse as FAIL under PEER_IDENTITY_BOUND
     and AGENT.A2A.PEER_IDENTITY_BINDING
```

All assertions are parsed JSON through `assert-json.py`. No verdict is matched
by substring.

---

## 7. Executed evidence

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean, 0 issues |
| `cargo test -p dare-a2a-security` | **356 passed, 0 failed** |
| `cargo test --workspace` | **3759 passed, 0 failed** |
| `scripts/k20/assert_no_real_credentials.py` | pass — 33 shipping, 5 test files, 2 artifacts |
| `scripts/k20/verify_proof_citations.py` | pass — 103 names against 754 tests |
| `cargo audit` | exit 0; 1 pre-existing allowed warning (yanked `chacha20`) |
| `run-ci-job-locally.py … a2a-security-2026` | **29/29 steps passed** |

---

## 8. Commits

```text
8960fe5  test(a2a): reproduce cycle-020 false-pass authentication paths  (expected-red)
820822e  fix(a2a): require positive verification for message authenticity
cca99ae  fix(a2a): enforce peer identity positive binding contract
e294b8c  fix(a2a): bind security requirement satisfaction to a successful verification
82eaf44  test(a2a): add the uncertain-authentication regression matrix
e3309fc  test(a2a): add A2A-LAB vectors for the positive-evidence contracts
5b20d33  ci(a2a): gate the cycle-020 positive authentication semantics
c56e449  style(a2a): apply rustfmt to the hotfix changes
```

---

## 9. Non-claims

A `PASS` still means only that the applicable invariants remained satisfied
under the local evidence analysed. This hotfix does not widen that claim; it
removes cases where the engine made it without the evidence to support it.

Nothing here validates a remote agent, contacts a peer, resolves a key or
verifies a credential. Authentication verification remains recorded evidence
produced by another verifier, read as local data.
