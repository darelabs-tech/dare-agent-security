# task-057 — Write PROOF.md

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

State what the cycle claims and name the test that decides each claim — with the naming itself checked mechanically.

## Files changed

- `DARE/cycles/020-a2a-inter-agent-security/PROOF.md` (new)
- `scripts/k20/verify_proof_citations.py` (new)
- `.github/workflows/ci.yml` (the citation gate as a CI step)

## Fourteen sections, each a claim table

Scope and totals; the claim boundary; the offline boundary; missing evidence never becoming success; coverage meaning a question was asked *and answered*; the sixteen distinctions; the corpus testing the engine rather than the fixture author; a report naming only what was observed; hostile input refused at the door; additive compatibility; determinism; the artifact accounting for itself; the CI gate; and — last — what the cycle does **not** claim.

The final section is the one a reader should be able to find. It says plainly that no PASS asserts a remote agent is secure, that the engine verifies no signature and resolves no key, that it takes verdict authority over no other cycle, and that Cycles 021, 022 and 023 remain out of scope with no task having required them.

## The citation gate caught ten invented names

`scripts/k20/verify_proof_citations.py` extracts every backticked name from `PROOF.md` and requires each to resolve to a test in the tree, to an allowed function citation verified by a `fn` search, or to a name the regression record says was removed (which must then be **absent**).

Its first run failed with ten unverified citations:

```
a_card_signature_may_not_be_recorded_by_the_local_policy — cited as a test, not found
a_file_name_that_names_no_document_kind_is_refused — cited as a test, not found
a_scenario_carries_no_executable_hook — cited as a test, not found
an_identifier_shaped_like_a_path_or_a_url_is_refused — cited as a test, not found
an_identifier_that_renders_differently_from_how_it_compares_is_refused — cited as a test, not found
authentication_evidence_may_not_come_from_the_agent_card — cited as a test, not found
every_credential_marker_is_written_the_way_it_is_compared — cited as a test, not found
only_local_policy_may_establish_approval — cited as a test, not found
the_authorization_subject_is_never_a_provider_or_an_endpoint — cited as a test, not found
the_registry_gained_exactly_the_ten_approved_properties — cited as a test, not found
```

Every one was a plausible-sounding name for a test that exists under a different name. Each was replaced with the real one — for example `only_local_policy_may_establish_approval` -> `only_a_local_source_may_establish_approval`, and `the_registry_gained_exactly_the_ten_approved_properties` -> `exactly_the_ten_approved_properties_were_added`.

This is exactly the defect the gate exists for. Cycle 016 shipped three such citations, Cycle 018 two, and Cycle 019 eleven — each time found only in review, and each time the document had read as authoritative. A proof whose citations are unchecked is a claim about a claim.

The verifier also refuses to succeed having found no citations or no tests, for the same reason the credential sweep does.

## One count corrected

`PROOF.md` first claimed 2799 regression tests in the CI job, which was the sum of two locally-run sets rather than what the job's regression step actually runs. Measured: **2202** in that step, and 3733 across the workspace. The number was corrected rather than the claim softened.

## Commands executed

```
python scripts/k20/verify_proof_citations.py
python -c "yaml.safe_load(...)"   # the CI file still parses with 28 steps
```

## Result

```
PROOF.md cites 103 names against 729 tests in the tree
  35 function citations allowed, 2 historical names
every cited name is verified
```

The gate now runs in CI as `Every test PROOF.md cites actually exists`, so a later rename that invalidates a citation fails the build rather than being found in review.

## Review result

**REVIEW PASS**
