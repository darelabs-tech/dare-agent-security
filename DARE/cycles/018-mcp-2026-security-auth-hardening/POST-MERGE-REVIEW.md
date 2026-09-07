# Cycle 018 — Post-merge security review

Cycle 018 merged as `4e2da94e6738cbecfa7a5243f4928e75c01c2e5b` with 21/21 CI
checks green and 2799 tests passing. A review afterwards found **eleven
defects**: nine paths that could report `PASS` on an authentication or
authorization control that had not held, and two hygiene problems.

The reason all 2799 tests were green is worth stating first, because it is the
lesson rather than the incident.

> The tests asserted the behaviour the engine **had**, not the behaviour the
> cycle **claimed**. Several of them encoded the defect directly:
> `casing_alone_is_not_an_authorization_relevant_change` asserted that a
> case-changed operation name was not a change;
> `every_surface_and_property_is_reachable_from_some_invariant` asserted that
> nine of ten properties were reachable and named the tenth as deliberately
> unreachable. Both passed. Both were wrong.

A suite written after the implementation describes it. Green means the
description is accurate, not that the thing described is correct.

- **Baseline:** `main @ 4e2da94e6738cbecfa7a5243f4928e75c01c2e5b`
- **Branch:** `fix/cycle-018-post-merge-security-review`

---

## F01 — HIGH — routing comparison folded case

**Was:** `normalize_routing_value()` returned `value.trim().to_ascii_lowercase()`.

**The false PASS.** A gateway routing on `Mcp-Name: DeleteInvoice` while the
server executed `deleteinvoice` compared equal, so
`MCP_NAME_HEADER_BODY_BINDING_PRESERVED` returned PASS. The same held for the
method.

**Why it was wrong.** The justification confused two different rules. An HTTP
*header name* is case-insensitive (RFC 9110 §5.1); a header *value* is an opaque
octet sequence whose meaning belongs to whoever defined the field. Here the
values are a JSON-RPC method and an MCP tool name, and a server's tool registry
is keyed by the literal string it published. `deleteInvoice` and `deleteinvoice`
are two different keys, or one key and one miss. Nothing in MCP `2026-07-28`
declares them equivalent.

**Now:** only surrounding whitespace is removed, and only because RFC 9110 §5.5
defines a field value as excluding it — a proof, not a preference. Everything
else compares exactly.

**Tests:** `protocol::a_case_changed_operation_name_never_escapes_the_binding`,
`no_case_variant_of_a_routing_value_compares_equal` (six pairs, swept rather
than sampled), `only_transport_padding_is_normalized_away`,
`identical_values_still_agree`;
`post_merge_regressions::f01_*` (3 end-to-end).

`comparison_is_semantic_rather_than_byte_exact` asserted the defect and was
rewritten, not deleted.

---

## F02 — HIGH — Cycle 003 was cited but never called

**Was:** `compat::authorization_relevant_change()` compared `method`, `name` and
`resource` with its own string comparison. `PROOF.md` claimed the decision came
from `dare_coaz_integrity::compute_authorization_binding` and
`changed_operation_fields`. Neither was called.

**The false PASS.** A permit issued for `payments.send(amount=100)` covered
`payments.send(amount=10000)`: same method, same name, same resource, so the
comparison found nothing. The same held for a changed principal, a changed
tenant and a changed scope set — every dimension where authorization actually
lives except the three that happened to be listed.

**The citation was wrong twice.** `changed_operation_fields` maps one of Cycle
003's own fixture mutation *kinds* to the field names it touches. It is a
fixture helper, not a general comparison, and could not have done the job it was
credited with.

**Now:** `compat.rs` assembles a `BindingMaterialV1` for each end and asks Cycle
003. The decision is `bindings_equal(compute_authorization_binding(authorized),
compute_authorization_binding(performed))`. Cycle 018 contributes the projection
and the *name* of whichever dimension moved; it contributes no policy.

Attribution is done by rebuilding the authorized projection with one dimension
replaced by the performed value and asking Cycle 003 whether the binding moved —
so even "which field changed" is Cycle 003's answer, not a second comparison.

### Exact APIs reused

| API | From | Used for |
|---|---|---|
| `binding::BindingMaterialV1` | `dare-coaz-integrity` | the versioned projection carrying both ends |
| `binding::binding_material_v1` | `dare-coaz-integrity` | assembling it from normalized fields |
| `binding::compute_authorization_binding` | `dare-coaz-integrity` | the binding digest |
| `binding::bindings_equal` | `dare-coaz-integrity` | **the decision** |
| `canonical::CanonicalValue::normalize` | `dare-coaz-integrity` | canonical form of mapped and trusted inputs |
| `result::MappingIdentity` | `dare-coaz-integrity` | identifying Cycle 018's one projection shape |
| `result::AuthorizationBinding` | `dare-coaz-integrity` | the binding type itself |

### Authorization dimensions now bound

`method`, `name`, `resource`, mapped `arguments` (mapped inputs); `principal`,
`tenant`, `scopes` (trusted inputs). The mapped/trusted split follows Cycle
003's own: the first is what the operation is and what it operates on, the
second is the context the decision was made in.

**Tests:** `compat::*` (18, including
`the_decision_comes_from_cycle_003_rather_than_a_local_comparison`,
`a_mutated_argument_is_authorization_relevant`,
`key_order_in_arguments_is_not_a_change`);
`post_merge_regressions::f02_*` (8 end-to-end, covering argument, principal,
tenant and scope mutation, plus the re-evaluated and refused controls).

`casing_alone_is_not_an_authorization_relevant_change` asserted the defect and
was replaced by `a_case_changed_operation_name_is_authorization_relevant`.

---

## F03 — HIGH — "evidence exists" was read as "evidence is favourable"

**Was:** `has_validity_evidence()` counted `VERIFIED`, `REJECTED` and `EXPIRED`
as evidence, which is correct for the question *was it examined?* The evaluator
then used it to answer a different question: *may it be relied on?*

**The false PASS.** A token the deployment's own verifier had **rejected**, or
one **past its window**, that the resource accepted anyway, reported PASS. It
had been examined, so evidence existed, so nothing fired.

**Also:** observing `TOKEN_CLAIMS_CONTEXT` satisfied the coverage contract for
`TOKEN_VALIDITY_EVIDENCE_PRESENT` outright. A run that saw a token with
`UNKNOWN` validity and never accepted it therefore reported PASS — stating that
validity evidence was present about a token nobody had checked.

**Now:** `TokenValidityState::may_be_accepted()` is true only for `VERIFIED`.
Accepting a token in any other state is a finding, with the reason naming which
state. The coverage contract is not satisfied by an unverified token projection:
the projection is the container, not the answer.

| state | not accepted | accepted |
|---|---|---|
| `VERIFIED` | continues to issuer/audience/scope | continues |
| `REJECTED` | control working — no finding | **FAIL** |
| `EXPIRED` | control working — no finding | **FAIL** |
| `UNKNOWN` | **INCONCLUSIVE** | **FAIL** |

**Tests:** `post_merge_regressions::f03_*` (6), including
`f03_unknown_validity_never_reaches_pass_even_when_nothing_was_accepted` and
`f03_refusing_a_bad_token_is_the_control_working`.

---

## F04 — HIGH — the token's issuer was never checked

**Was:** `TokenClaims.issuer` existed and no evaluator read it.

**The false PASS.** A token minted by an authorization server the resource never
advertised, verified, and audienced for exactly this resource, was accepted. The
audience check asks whether the token names this resource — it does. Nothing
asked whether that issuer was ever allowed to issue for it.

**Now:** `token_issuer_boundary()` reports under
`AUTHORIZATION_SERVER_ISSUER_BOUNDARY_PRESERVED` when a token's issuer is
neither advertised by the resource nor the one selected. It adds no required
coverage channel, so a scenario with no token still answers the advertisement
question and one with a token gets the check for free.

Issuer, validity and audience remain three independent findings.
`f04_the_issuer_finding_is_independent_of_the_audience_finding` asserts that a
wrong issuer is not also reported as an audience violation.

**Tests:** `post_merge_regressions::f04_*` (3).

---

## F05 — HIGH — metadata provenance did not participate

**Was:** the PRM and issuer evaluators compared identifiers.

**The false PASS.** Consider a metadata document that says it is about
`mcp-invoices`, advertises `as-attacker`, and `as-attacker`'s own metadata
declaring its issuer as `as-attacker`, with the client selecting `as-attacker`.
Every identifier agrees. Checking ids alone finds a perfectly consistent set of
documents — written by whoever wanted the selection. Both were
`trust: SELF_REPORTED`, and nothing looked.

**Now:** provenance is checked before content. A metadata document whose trust
class cannot establish identity cannot establish which authorization servers may
issue for a resource, and a server's own `SELF_REPORTED` description of itself
cannot be what makes it authoritative — the same shape as `clientInfo` naming a
principal. Selection is treated as reliance: choosing a server because a
document advertises it is trusting that document.

`DECLARED` is not silently promoted. The project's contract has exactly one
class that may establish identity, and `f05_declared_metadata_is_not_silently_promoted_to_authenticated`
pins all three.

**Tests:** `post_merge_regressions::f05_*` (4, with the `AUTHENTICATED` benign
control).

---

## F06 — MEDIUM — a finding filed under a name that did not describe it

**Was:** `identity_boundary_violation()` reported a promoted `clientInfo` as
`INBOUND_CREDENTIAL_NOT_REUSED_AS_UPSTREAM_AUTHORITY`. The registry property
`MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY` existed, was `REQUIRED` in the
profile, and no invariant reported under it.

Two tests encoded this as intended: `every_surface_and_property_is_reachable_from_some_invariant`
asserted `properties.len() == 9` and that the tenth was absent, and
`McpAuthScenario::validate` carried an explicit exemption letting a scenario
declare that property while naming a different invariant.

**Now:** `SELF_REPORTED_METADATA_NOT_AUTHORITY` exists. **Fourteen invariants
became fifteen.** The count was not worth protecting: a finding that does not
name what it is about sends an operator to the wrong place, and promoting
`clientInfo` to a principal is a different problem from forwarding a caller's
credential upstream, with a different fix.

Updated: enum, `all()`, `as_str()`, `surface()`, `property()`, the coverage
contract, the scenario schema enum, the lab generator, labs 029 and 030, the
corpus, the hostile manifest, the counting tests, the book, and the validation
exemption — which was **removed**, so the property/surface consistency check is
total again.

It is both selectable *and* checked unconditionally: selectable so a scenario
can exercise it; unconditional because a deployment that derived its principal
from `clientInfo` is broken whatever else the run was examining.

**Tests:** `model::the_fifteen_invariants_are_closed_and_uniquely_named`,
`the_self_reported_boundary_no_longer_borrows_the_credential_invariants_name`,
`the_approved_invariant_names_are_exactly_these`;
`lab_scenarios::the_labs_between_them_exercise_every_invariant` (now exact — it
asserted `>= 10` before, loose enough for three invariants to stop being
exercised unnoticed); `post_merge_regressions::f06_*` (3).

Labs 029 and 030 also stopped bypassing the evaluator. They carried their own
`Expectation` variants that loaded the fixture and asserted nothing about what a
run concluded; they are ordinary `Pass`/`Fail` entries now.

---

## F07 — MEDIUM — a deterministic finding with no deciding evidence

**Was:** the self-report violation shipped `deciding_event_digests: Vec::new()`,
in a crate whose own contract says a finding without deciding evidence is an
assertion rather than a finding.

**Now:** the evaluator reads the `MCP_IDENTITY_METADATA` observation and digests
it, so the finding names evidence the artifact retained. `normalize` emits that
observation exactly when there is self-description — which is exactly when the
boundary can be crossed — so the evidence-bound path always fires. No digest is
invented.

**Tests:** `post_merge_regressions::f07_the_self_report_finding_carries_deciding_evidence_that_was_retained`,
which also checks the digest names an event present in the artifact;
`every_new_finding_still_names_the_evidence_that_decided_it` sweeps every new
FAIL path.

---

## F08 — MEDIUM — the budget counted bytes it did not bound

**Was:** the ledger charged each event and stopped counting at the ceiling,
then stored the whole observation vector anyway. `retained_bytes` described a
smaller artifact than the one written.

**Now:** admission and retention are the same act. An event that was not charged
is not kept, not evaluated and not written, so accounted bytes, evaluated bytes
and persisted bytes are the same bytes.

A trial stopped by **any** hard bound before its evidence was complete cannot
report PASS; it reports INCONCLUSIVE. "We saw no violation" and "we stopped
looking" are different statements, and only the first is a pass. A FAIL stands,
because every violation was decided by an event that *was* admitted.

Writing the test found a second thing: with eight requests per trial, the
**request** budget (`HARD_MAX_TOTAL_REQUESTS = 24`) is reached before the byte
budget, and that path had the same problem. The guard covers both.

**Tests:** `post_merge_regressions::f08_*` (4), including
`f08_accounted_bytes_are_the_bytes_actually_persisted` and
`f08_a_budget_that_stopped_the_evidence_never_yields_pass`, which asserts the
fixture still exhausts the budget so the test cannot pass vacuously.

---

## F09 — MEDIUM/LOW — `--trials` could widen approved authority

**Was:** `with_trial_override` checked only `HARD_MAX_TRIALS`. A scenario
approving 3 trials could be run 10 times from the command line — under the crate
ceiling, and more than the scenario granted. The doc comment already claimed the
narrowing guarantee.

**Now:** an override above the scenario's own count is refused. The flag is a
reduction, not a second approval.

**Tests:** `trials::an_override_can_never_widen_what_a_scenario_approved`,
`an_override_may_narrow_what_a_scenario_approved`;
`post_merge_regressions::f09_*` (2); CI step *A trial override may narrow what a
scenario approved, never widen it*, which also asserts no artifact is written on
refusal.

`an_override_may_narrow_but_never_widen_past_the_hard_bound` claimed a guarantee
it did not check and was renamed to
`an_override_is_refused_above_the_crate_hard_maximum`, which is what it tests.

---

## F10 — HYGIENE — the cycle closed with a stale header

`TASKS.md` still read `IN PROGRESS — 37/48 tasks closed; the release gate is NOT
met and no PR is open` after the cycle had closed and merged. Corrected to
`COMPLETE — 48/48`, with the post-merge review recorded. The execution history
below the header is untouched: a record edited to look better afterwards is not
a record.

---

## F11 — HYGIENE — compiled Python in the repository

Three `.pyc` files under `scripts/k18/__pycache__/` were committed — a
by-product of the generators importing one another. Removed from tracking, and
`.gitignore` now covers `__pycache__/` and `*.py[cod]`. No source script was
touched.

---

## What this review did not change

- No new dependency, no egress, no state change, no live OAuth, OIDC, JWKS, MCP
  endpoint or IdP. The three local modes are unchanged.
- No draft or open proposal became a requirement. Standards statuses are as
  Cycle 018 pinned them, still unverified upstream.
- No earlier cycle's properties, profiles or denominator semantics moved.
- No existing test was deleted to make the suite pass. Three were **rewritten**
  because they asserted the defect, and two were **renamed** because their names
  claimed more than they checked; each is named above with what it used to say.

## Residual risks

- **The v1 registry property count is unchanged at 20 and the profile still
  selects 10.** F06 added an invariant, not a property. The registry did not
  need to move, but a reader comparing "15 invariants" to "10 properties" should
  know the two do not map one-to-one and never did.
- **`DECLARED` metadata is treated as unable to establish authority**, which is
  what `TrustClass::may_establish_identity()` has always said. If a deployment
  means something stronger by `DECLARED`, that is a design question for a later
  cycle, not a code change here.
- **Argument mutation is detected structurally, over declared values.** Cycle
  018 observes no real request bodies, so a deployment whose mapped arguments
  are not recorded in the projection contributes nothing to the binding — the
  same gap the coverage contract reports elsewhere as INCONCLUSIVE rather than
  PASS.
- **The standards statuses remain pinned as of Cycle 018 with no upstream
  re-verification**, as the provenance record's own `reverification_note` says.
