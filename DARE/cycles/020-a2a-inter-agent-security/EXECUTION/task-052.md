# task-052 — Implement `a2a-security-2026` CI job

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Gate the cycle in CI, with structured assertions and without a single substring check.

## Files changed

- `.github/workflows/ci.yml` (new job `a2a-security-2026`, 27 steps)

## No substring assertions anywhere

Every verdict, class, invariant, property and count is asserted through `scripts/assert-json.py`, which parses the artifact and compares whole values. There is no `grep` for a verdict token in this job.

That is not stylistic. `SECURE` matching inside `INSECURE_INTER_AGENT_COMMUNICATION` cost Cycle 013 a red build, and this cycle's risk family is *literally that string* — a substring gate here would have been the same failure with the same name.

The one step that needs more than equality — "one exchange crossing three boundaries reports three" — uses an inline Python block that parses the violations and does set arithmetic on the invariant names. Still structure, never text.

## What each step decides

Seven test steps cover the engine, the corpus, the missing-evidence regressions, the generators, the profile, the properties and standards, and the CLI flag surface.

Fourteen end-to-end steps run the actual binary and assert on the actual artifacts:

| Step | Vector | Asserted |
|---|---|---|
| an exchange that agrees with its approvals | `A2A-LAB-001` | exit 0, PASS, all six artifacts present, 14 outcomes, 0 violations, zero state changes, zero egress |
| the card in hand is not the card policy pinned | `A2A-LAB-002` | exit 2, FAIL, `DISCOVERY_BINDING_PRESERVED` |
| a valid signature over a different envelope | `A2A-LAB-019` | exit 2, FAIL, `AGENT.A2A.MESSAGE_AUTHENTICITY` |
| authenticating is not being authorized | `A2A-LAB-016` | exit 2, FAIL, `AGENT.A2A.SKILL_AUTHORIZATION` |
| peer content that became instruction | `A2A-LAB-021` | exit 2, FAIL, `AGENT.A2A.AUTHORITY_PROPAGATION` |
| delegation is not privilege amplification | `A2A-LAB-028` | exit 2, FAIL, `AUTHORITY_PROPAGATION_BOUNDED` |
| a tenant routing value is not proof | `A2A-LAB-032` | exit 2, FAIL, `AGENT.A2A.TENANT_BOUNDARY` |
| missing message authentication | `A2A-LAB-018` | exit 2, **INCONCLUSIVE**, 0 violations |
| a card nothing approved | `A2A-LAB-004B` | exit 2, **INCONCLUSIVE**, 0 violations |
| three boundaries at once | `A2A-LAB-050` | exit 2, all three invariants present in `violations` |
| an oversized Agent Card | `A2A-LAB-006` | exit 1, ERROR, 0 peers, 0 exchanges |
| a credential-bearing Agent Card | `A2A-LAB-053` | exit 1, ERROR |
| an unknown vector | `A2A-LAB-999` | exit 3 |
| replay without a local policy | — | exit 3 |

The two INCONCLUSIVE steps are the ones that matter most. They assert `verdict=INCONCLUSIVE` **and** `--count violations=0` together, which is the only combination that distinguishes "no evidence to decide on" from both "clean" and "broken". Either assertion alone would pass for the wrong reason.

`--count violations=0` also depends on the field being serialized when empty — the Cycle 019 defect that broke exactly this check, corrected in `result.rs`.

## Two claim-boundary gates

`Every artifact this job wrote states its claim boundary` walks every `summary.md` the job produced and requires both "not a statement that a remote agent is secure" and "No agent was contacted". It fails if it finds no summaries at all, because a check that read nothing would pass by reading nothing.

`No artifact this job wrote carries a credential or live endpoint` runs the sweep a second time, after the CLI has written artifacts under `.dare-agent-security/`, so it covers what a run *produces* and not only what the repository *contains*.

## Regressions

The final step runs Cycles 012 through 019 in full, including `dare-supply-chain-security`, which the Cycle 019 job did not need to run against itself.

## Commands executed

```
python scripts/run-ci-job-locally.py .github/workflows/ci.yml a2a-security-2026
```

## Result

**All 25 run-steps passed on the first local execution.**

```
running 25 run-steps from .github\workflows\ci.yml:a2a-security-2026
[PASS] Engine unit tests (types, bounds, importers, evaluators, adapters, artifact)
[PASS] The A2A-LAB entries against the harness contract
[PASS] Missing evidence is inconclusive and a multi-violation run reports every crossing
[PASS] Generators are reproducible and no fixture carries a credential
[PASS] A2A profile and coverage integration
[PASS] A2A properties and standards provenance
[PASS] CLI flag surface (no endpoint, token, key, webhook, fetch or shell flag)
[PASS] No real credential, key or live identity endpoint anywhere
[PASS] Offline CLI - an exchange that agrees with its approvals
[PASS] The card in hand is not the card policy pinned
[PASS] A valid signature over a different envelope is not authenticity
[PASS] Authenticating is not being authorized
[PASS] Peer content that became instruction crossed a boundary
[PASS] Delegation is not privilege amplification
[PASS] A tenant routing value is not proof of tenant authorization
[PASS] Missing message authentication is inconclusive and never a pass
[PASS] A card nothing approved is undecidable rather than clean
[PASS] One exchange crossing three boundaries reports three
[PASS] An oversized Agent Card is refused rather than parsed
[PASS] A credential-bearing Agent Card is refused at the door
[PASS] An unknown corpus vector is refused rather than run empty
[PASS] Replay analyses a capture and never re-sends it
[PASS] Every artifact this job wrote states its claim boundary
[PASS] No artifact this job wrote carries a credential or live endpoint
[PASS] Cycle 012 to 019 regressions still pass

all 25 steps PASSED
```

Cycle 019's first local CI run found a real defect (a compliant vector reporting INCONCLUSIVE). This one found none, because that correction — `applicable` on outcomes — was built into this cycle from task-037 rather than retrofitted.

## Deviations

The expected verdicts were established by running the binary and reading the artifacts before writing the assertions, rather than predicted. One result was not what the corpus classification suggested: `A2A-LAB-033` is a GAP for I09 and aggregates to **FAIL**, because `user-unknown` also holds no skill grant and I05 reports it. The engine is right — a concrete failure outranks an undecided answer — so `A2A-LAB-018` and `A2A-LAB-004B` were used for the INCONCLUSIVE steps instead, where the aggregate really is undecided.

## Review result

**REVIEW PASS**
