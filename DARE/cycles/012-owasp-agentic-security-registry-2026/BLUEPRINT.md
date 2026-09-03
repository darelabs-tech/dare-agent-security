# Cycle 012 - Blueprint

**Status:** ARCHITECTURE PROPOSED  
**Approval:** PENDING

## 1. Architecture intent

Cycle 012 extends the existing registry/coverage architecture without creating a parallel security engine.

```text
Standards snapshots
  -> Property Schema vNext
  -> Agentic Property Registry
  -> Agentic Baseline Profile
  -> Existing Coverage Engine
  -> Coverage / Evidence-aware Result
  -> Existing Product Reports / CI
```

## 2. Compatibility strategy

Prefer additive evolution.

Existing:

```text
MCP.* properties
mcp-security-baseline
Cycle 001 evidence contracts
Cycle 006 coverage math
```

New:

```text
AGENT.* properties
agentic-security-baseline-2026
Agentic categories/predicates
standards provenance metadata
risk-family metadata
```

No existing MCP property is renamed.

## 3. Schema plan

Introduce a versioned schema revision that supports multiple property namespaces while preserving existing serialized registry entries.

Candidate ID constraint:

```regex
^(MCP|AGENT)\.[A-Z][A-Z0-9_.]+$
```

Do not reserve acceptance for future namespaces in validation until those namespaces are actually introduced by an approved cycle.

## 4. Registry shape

Each registry entry should expose:

```json
{
  "id": "AGENT.GOAL.INSTRUCTION_INTEGRITY",
  "title": "Instruction and goal integrity",
  "risk_family": "AGENT_GOAL_HIJACKING",
  "category": "GOAL_INTEGRITY",
  "description": "...",
  "applicability": { "predicates": ["agent_present"] },
  "supported_modes": ["static", "passive"],
  "evidence": { "required_for_confirmed_verdict": true },
  "standards": [
    {
      "source": "OWASP_AGENTIC_TOP10_2026",
      "reference": "Agent Goal Hijacking",
      "status": "NORMATIVE"
    }
  ]
}
```

Exact field names are frozen only after schema-task review.

## 5. Risk families

Use a closed enum for the ten 2026 Agentic risk families:

```text
AGENT_GOAL_HIJACKING
TOOL_MISUSE_EXPLOITATION
IDENTITY_PRIVILEGE_ABUSE
AGENTIC_SUPPLY_CHAIN
UNEXPECTED_CODE_EXECUTION
MEMORY_CONTEXT_POISONING
INSECURE_INTER_AGENT_COMMUNICATION
CASCADING_FAILURES
HUMAN_AGENT_TRUST_EXPLOITATION
ROGUE_AGENTS
```

## 6. Predicate architecture

Predicates remain declarative data, not executable expressions.

The applicability engine receives normalized facts and evaluates a closed enum.

```text
normalized facts
  -> predicate evaluation
  -> property applicability
  -> assessment plan
```

## 7. Coverage integration

The current coverage engine remains authoritative for APPLICABLE / NOT_APPLICABLE / NOT_TESTED / OUT_OF_SCOPE / BLOCKED semantics.

Additive result metadata may include risk-family grouping. Existing denominator math must remain unchanged unless a future schema version explicitly changes it.

## 8. Standards snapshot

Commit a local standards snapshot/manifest containing source name, title, version/year, retrieval date, canonical reference and mapping notes.

No runtime network dependency is allowed for schema or standards validation.

## 9. Security boundaries

Registry and profile inputs are untrusted.

Validation pipeline:

```text
load local artifact
 -> size/path safety
 -> JSON/schema validation
 -> closed enum validation
 -> duplicate/reference validation
 -> canonical ordering
 -> coverage consumption
```

No scripts, callbacks, dynamic expressions, shell fragments or embedded executable policy are accepted.

## 10. Test architecture

Required test classes:

```text
schema positive fixtures
schema negative fixtures
legacy MCP regression
agentic registry integrity
profile reference integrity
duplicate ID rejection
unknown predicate rejection
unknown risk-family rejection
malformed standards mapping rejection
coverage compatibility
stable ordering/canonicalization
confidential/offline regression
```

## 11. Reporting

Existing reports may display:

```text
Agentic risk family
Property ID
Applicability
Coverage status
Verdict when available
Evidence references
Standards mapping
```

A risk family with zero tested applicable properties must never be rendered as secure.

## 12. CI gate

Add a dedicated Cycle 012 CI gate that validates:

```text
all schemas
full registry
agentic baseline
legacy MCP baseline
negative fixtures
coverage engine regression
product report compatibility
cargo fmt/clippy/test/audit remain green
```

## 13. Migration rule

If the property schema version changes, provide deterministic migration/compatibility behavior and document whether v1 registries remain directly valid or require an adapter.

Silent reinterpretation of an existing property is prohibited.

## 14. Completion architecture

At completion:

```text
DARE Agent Security
  -> understands MCP baseline
  -> understands Agentic 2026 baseline
  -> can plan coverage deterministically
  -> can report NOT_TESTED honestly
  -> has a standards-grounded foundation for Cycles 013+
```
