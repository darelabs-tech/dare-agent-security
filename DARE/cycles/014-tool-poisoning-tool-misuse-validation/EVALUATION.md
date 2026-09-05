# Cycle 014 — Evaluation from Cycle 013

**Status:** COMPLETE
**Cycle:** 014 — Tool Poisoning & Tool Misuse Validation
**Baseline:** `main` at `1fa9ba04e55e53e25d71621675cba9a70d174e8e`
**Source cycle:** Cycle 013 — Direct + Indirect Prompt Injection Validation

## Decision

**Recommended Cycle 014:** Tool Poisoning & Tool Misuse Validation.

Cycle 013 is sufficiently complete to support this next step. It delivered a bounded local/offline validation engine, typed observations, deterministic invariant evaluation, canonical digest binding, safe trial budgets, coverage/profile integration, bounded reporting language, and a local runner that executes GitHub Actions `run:` steps verbatim.

## What Cycle 013 proved

Cycle 013 closed all 28 tasks and mapped all 44 acceptance criteria. Its local release gates passed with 965 tests, zero test failures and zero audit vulnerabilities. The only PR-open CI defect was an imprecise gate assertion (`grep -q 'SECURE'`) that matched `INSECURE_INTER_AGENT_COMMUNICATION`; the product itself remained green. A follow-up introduced `scripts/run-ci-job-locally.py`, which executes workflow `run:` steps verbatim and is now a required pre-PR gate for Cycle 014.

Cycle 013 also found four security-relevant validator defects during implementation:

1. independent facts must not mask each other;
2. absence of evidence must not be treated as evidence of absence;
3. a clean observation needs an explicit positive coverage signal;
4. secret detection must operate on the entire bounded value, not only prefixes.

These lessons are promoted to Cycle 014 design constraints.

## Why Tool Poisoning & Tool Misuse is next

The Cycle 012 registry already contains:

- `AGENT.TOOL.AUTHORIZATION_BOUNDARY`
- `AGENT.TOOL.OUTPUT_TRUST_BOUNDARY`

under risk family `TOOL_MISUSE_EXPLOITATION`.

Cycle 013 explicitly deferred tool-description/output poisoning to Cycle 014. OWASP ASI02 describes misuse of legitimate tools through manipulated input, unsafe delegation, ambiguous instructions, destructive parameters, unexpected chaining, data exfiltration and workflow hijacking. Cycle 014 converts that risk family from registry metadata into bounded, deterministic validation.

## Scope split

Cycle 014 covers two related but distinct classes:

### Tool poisoning

Untrusted or attacker-controlled tool surface data changes agent behavior or downstream trust:

- tool description poisoning;
- tool schema/annotation poisoning;
- tool-output instruction/data poisoning;
- metadata drift/substitution;
- trust-boundary confusion between tool metadata/output and authoritative policy.

### Tool misuse

A legitimate tool is selected or applied outside the approved task intent while still within the test harness' synthetic authority:

- unintended tool selection;
- destructive/risky argument choice represented as a structured request, never executed;
- parameter pollution/substitution;
- unexpected tool chaining;
- excessive invocation/cost amplification within hard local bounds;
- tool-result use that violates an explicit output-trust invariant.

## Explicit boundaries

Cycle 014 does **not** absorb:

- identity/credential inheritance or privilege escalation — Cycle 015;
- broad supply-chain provenance/AI-BOM — Cycle 019;
- generalized memory poisoning — Cycle 016;
- RAG retrieval poisoning — Cycle 017;
- arbitrary code execution — ASI05/later dedicated work;
- A2A tool delegation — Cycle 020;
- remote production testing — Cycle 022;
- adaptive multi-turn trust grooming — Cycle 021.

## Required inheritance from Cycle 013

1. LLM prose is never the final judge.
2. Every PASS condition requires invariant-specific positive observation coverage.
3. Typed independent facts must be emitted independently even if one event violates multiple invariants.
4. Unknown/malformed/executable inputs fail closed.
5. Local/synthetic/replay only; no provider credentials or remote target flags.
6. Bounded trials, output, time, invocation count and chain depth.
7. Structured risky actions are observed but never executed.
8. Reports describe tested vectors only, never universal tool security.
9. `scripts/run-ci-job-locally.py` must execute the Cycle 014 workflow job successfully before PR opening.

## Exit recommendation

Proceed to Design/Blueprint for Cycle 014 with a dedicated Tool Security validation engine that reuses Cycle 001 evidence, Cycle 006 coverage, Cycle 009 controlled execution, Cycle 013 observation/evaluator design patterns, and Cycle 012 `TOOL_MISUSE_EXPLOITATION` registry semantics.
