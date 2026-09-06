# Cycle 016 — Frozen Baseline

Measured on this machine at the branch head, before any Cycle 016 implementation
change. Every number here was produced by running the stated command, not read
from a previous cycle's record.

## Environment

| Field | Value |
|---|---|
| Baseline | `main @ 9d543ae0ec202b7ad05a852179ca5703857a317a` |
| Branch head at freeze | `aeb40844a28af33cb30c5b1840e27e2945cc9ade` |
| Branch | `agent/cycle-016-memory-context-poisoning-security` |
| Toolchain | `rustc 1.94.1 (e408947bf 2026-03-25)` |
| Cargo | `cargo 1.94.1 (29ea6fb6a 2026-03-24)` |
| Platform | Windows 11 (x86_64-pc-windows-msvc) |
| Local CI shell | Git Bash (`C:\Program Files\Git\bin\bash.exe`) |
| Date | 2026-09-05 |

The branch head differs from the baseline only by Cycle 016 planning documents
(44 files, 1133 insertions, no code).

## 1. Workspace test baseline

```
cargo test --workspace
```

**1716 passing, 0 failing, across 176 test binaries.**

## 2. Per-crate baseline

Each measured with `cargo test -p <crate>`.

| Crate | Passing |
|---|---|
| `dare-security-evidence` (Cycle 001) | 75 |
| `dare-coaz-integrity` (Cycle 003) | 124 |
| `dare-coverage` (Cycle 006/012) | 144 |
| `dare-adversarial` (Cycle 009) | 14 |
| `dare-prompt-injection` (Cycle 013) | 271 |
| `dare-tool-security` (Cycle 014) | 276 |
| `dare-identity-security` (Cycle 015) | 323 |
| `dare-product` | 59 |
| `dare-mcp-lab` | 28 |

These are the numbers Cycle 016 must leave unchanged. Any movement in them is a
regression, not an improvement.

## 3. Registry and profile baseline

| Measure | Value |
|---|---|
| v1 registry properties | 10 |
| v2 registry properties | 30 |
| v2 applicability predicates | 28 |
| v2 property categories | 22 |
| Assessment profiles | 5 |
| Workspace crates | 14 |
| CLI `validate` subcommands | 9 |
| CI jobs | 13 |

Profiles present: `agentic-security-baseline-2026`, `identity-security-baseline-2026`,
`mcp-security-baseline`, `prompt-injection-baseline-2026`, `tool-security-baseline-2026`.

## 4. The two memory properties, pinned field by field

Cycle 016 may add alongside these. It may not rename, re-scope or re-word them.
Both are recorded here in full so a later diff is unambiguous.

### `AGENT.MEMORY.CONTEXT_INTEGRITY`

```json
{
  "id": "AGENT.MEMORY.CONTEXT_INTEGRITY",
  "title": "Memory and context integrity",
  "risk_family": "MEMORY_CONTEXT_POISONING",
  "category": "MEMORY_CONTEXT",
  "description": "Persisted memory and context must retain provenance and integrity boundaries before influencing future agent decisions.",
  "applicability": { "predicates": ["agent_present", "memory_present"] },
  "supported_modes": ["static", "passive"],
  "evidence": {
    "required_for_confirmed_verdict": true,
    "accepted_classes": ["STATIC", "TRACE", "CONFIGURATION"]
  },
  "standards": [
    {
      "source": "OWASP_AGENTIC_TOP10_2026",
      "reference": "ASI06 Memory and Context Poisoning",
      "status": "NORMATIVE"
    }
  ],
  "maturity": "EXPERIMENTAL"
}
```

### `AGENT.MEMORY.TENANT_BOUNDARY`

```json
{
  "id": "AGENT.MEMORY.TENANT_BOUNDARY",
  "title": "Memory tenant boundary",
  "risk_family": "MEMORY_CONTEXT_POISONING",
  "category": "MEMORY_CONTEXT",
  "description": "Agent memory must not cross principal or tenant boundaries without explicit authorization.",
  "applicability": {
    "predicates": ["agent_present", "memory_present", "authorization_present"]
  },
  "supported_modes": ["static", "passive"],
  "evidence": {
    "required_for_confirmed_verdict": true,
    "accepted_classes": ["POLICY", "TRACE"]
  },
  "standards": [
    {
      "source": "OWASP_AGENTIC_TOP10_2026",
      "reference": "ASI06 Memory and Context Poisoning",
      "status": "NORMATIVE"
    }
  ],
  "maturity": "EXPERIMENTAL"
}
```

Both already carry `risk_family = MEMORY_CONTEXT_POISONING` and the ASI06
reference, so Cycle 016's four additions join an established family rather than
opening one.

## 5. Cross-cycle reuse map

What Cycle 016 takes from earlier cycles, and the exact symbol it takes.

| From | Reused | Not reused |
|---|---|---|
| Cycle 001 | `Verdict`, `SecurityEvidence`, `validate_secret_safety`, `RedactionMetadata` | — no second verdict vocabulary |
| Cycle 003 | `CanonicalValue::normalize` for any authorization-relevant projection | its authorization engine |
| Cycle 006 | `CoverageStatus`, applicability predicates, `math.rs` denominator semantics **untouched** | — |
| Cycle 009 | `kill_switch::inspect_step`, `budget_enforce::BudgetState`, `ExecutionBudget`, `ProofClass::SyntheticNoop` | — |
| Cycle 013 | the untrusted-data-vs-authoritative-instruction rule, `TrustLevel` shape | the prompt-injection evaluator; Cycle 016 is distinguished by *persistence and recall* |
| Cycle 015 | principal/tenant conventions, sanitized identifier rules, `PrincipalKind` shape | the identity evaluator; memory boundaries align with identity semantics rather than redefining them |

## 6. Expected additive movement

Predicted here so a later diff can be checked against a prediction rather than
rationalised after the fact.

| Measure | Before | Expected after |
|---|---|---|
| v2 registry properties | 30 | 34 |
| v2 applicability predicates | 28 | up to 32 |
| v2 property categories | 22 | 22 (reuses `MEMORY_CONTEXT`) |
| Assessment profiles | 5 | 6 |
| Workspace crates | 14 | 15 |
| CLI `validate` subcommands | 9 | 10 |
| CI jobs | 13 | 14 |
| Workspace tests | 1716 | greater, by the Cycle 016 suites only |

Nothing in the "before" column may decrease.

## 7. Inherited lessons

Carried from Cycle 015's regression record, each with what it changes here.

1. **Match secret *shape*, not vocabulary.** Cycle 015 shipped a sweep that
   fired on the honest sentence "without any bearer material", making a truthful
   description of the boundary unwritable. Memory fixtures will discuss stored
   credentials as a subject; the sweep must let them.
2. **Mask whole armoured blocks.** PEM masking that stops at the first
   whitespace leaves the key body in the retained text. Memory content is the
   most likely place for a multi-line secret to appear.
3. **Sweep values, not only field names.** A newline in a title can forge a log
   line; a bidi override can make two identifiers render identically. Memory IDs
   and namespaces are identifiers that end up in reports.
4. **A fixture must not be able to state its own verdict.** Any
   expected-verdict-shaped field — even one the evaluator never reads — is a
   coupling waiting to happen and is refused.
5. **Test that every invariant is reachable in both directions.** Cycle 015
   found two invariants no lab drove to `FAIL`. The corpus test must prove
   reachability rather than assume it.
6. **A control that cannot fire asserts nothing.** Cycle 015 shipped a
   kill-switch test whose condition was impossible by construction. Any
   safety-control test must be able to observe the control actually tripping.

## 8. Carried residual risks

From Cycle 015, still true here:

1. synthetic reference behavior is not production behavior;
2. a finite corpus bounds the claim;
3. boundaries are proven from declarations, not from touching real resources;
4. coverage contracts are per-invariant, not per-deployment;
5. the local CI runner is not GitHub Actions;
6. the adapters are the only observation source.

New for Cycle 016:

7. **Persistence is modelled, not exercised.** Cycle 016 reasons over a declared
   store snapshot. It connects to no database, cache or vector store, so a
   deployment whose real persistence differs from its declared model is outside
   what this can see. That is deliberate: proving it otherwise would mean
   touching real memory.
