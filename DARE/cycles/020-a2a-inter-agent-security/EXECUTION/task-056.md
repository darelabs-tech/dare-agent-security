# task-056 — Write REGRESSION.md

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Record every correction made during execution, what caused it, and what now prevents it from recurring silently.

## Files changed

- `DARE/cycles/020-a2a-inter-agent-security/REGRESSION.md` (new)

## What it records

Nine sections. The substantive ones are the first five:

1. **A word-ban refused the document's own denial — three times.** In the standards record ("bearer token"), in the staged bundle (`expected_audience`), and in the operator summary ("agent is secure"). Three unrelated places, one pattern, and it is the most repeated defect in this cycle. Each is now anchored on shape or on the claim rather than on the word.

2. **Two wire formats disagreed with their own prose.** `JSON_RPC` vs `JSONRPC`, and `O_AUTH2_AUTHORIZATION_CODE` / `OPEN_ID_CONNECT` vs what a real document carries. A document written with either spelling was readable by only half the engine.

3. **A behaviour named for a crossing staged no crossing.** `DuplicateNonIdempotentAction` used a skill the policy declares idempotent, so the repeat was genuinely safe.

4. **Two corpus entries were filed against the wrong answer** — `A2A-LAB-004` and `A2A-LAB-011`. In both, the fixture was corrected rather than the engine.

5. **The profile denominator test proved nothing, then proved the wrong thing.** It compared a profile against itself, and it asserted something false about the Cycle 012 baseline.

## The two sections that are not about failures

§7 lists corrections **carried in** from Cycles 013, 016, 018 and 019 rather than rediscovered — the self-accounting artifact budget, `violations` always serialized, `applicable` on outcomes, the comparison-not-just-presence coverage step, the brace-aware credential sweep, the lowercase credential list, and structured CI assertions instead of substring greps.

That last one is worth its own sentence: `SECURE` matches inside `INSECURE_INTER_AGENT_COMMUNICATION`, and that string **is this cycle's risk family**. A substring gate here would have reproduced Cycle 013's defect under the original name.

§9 records one place where the *expectation* was corrected against the engine's answer rather than the reverse: `A2A-LAB-033` aggregates to FAIL rather than INCONCLUSIVE, because the same unknown subject that makes I09 undecidable also holds no skill grant. No code changed.

## What it explicitly says did not change

The fourteen invariants and their semantics. The sixteen distinctions. The four verification statuses. The public property identifiers, including the two inherited. The `AGENT.A2A.*` namespace with no top-level `A2A.*`. The offline boundary, never loosened for any test, fixture or artifact.

## Commands executed

None. This document records work verified elsewhere; the verification is cited rather than repeated.

## Result

`REGRESSION.md` written, 9 sections.

## Review result

**REVIEW PASS**
