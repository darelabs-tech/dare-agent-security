# Cycle 017 — Frozen Baseline

**Baseline:** `main @ c0cd5edbb5a157d285b20177b7bd20a23b1811cc`
**Branch head at freeze:** `3346d3aa435492e38d03990b844e050ec4aa07c5`
**Frozen at:** 2026-09-06
**Toolchain:** rustc/cargo 1.94.1, edition 2021, Windows 11 msvc; Git Bash for the local CI runner

This document records what the workspace *was* before Cycle 017 changed anything,
so that "additive" can be checked against a number rather than asserted.

---

## 1. Test counts

`cargo test --workspace` at the baseline: **2067 passed, 0 failed**, across 133
test-result reports (114 of which run at least one test; the rest are empty
targets and doc-test harnesses).

| Crate | Tests |
|---|---:|
| `dare-security-evidence` | 75 |
| `dare-coaz-integrity` | 124 |
| `dare-coverage` | 186 |
| `dare-adversarial` | 14 |
| `dare-prompt-injection` | 271 |
| `dare-tool-security` | 276 |
| `dare-identity-security` | 323 |
| `dare-memory-security` | 265 |
| `dare-product` | 69 |
| `dare-agent-security` (CLI) | 235 |
| `dare-mcp-discovery` | 146 |
| **Workspace total** | **2067** |

Every one of these counts must still hold at the end of this cycle. A crate that
predates Cycle 017 and whose count *drops* has had something removed; one whose
count moves without a corresponding new test in this cycle needs explaining.

## 2. Coverage registry and profiles

| Measure | Baseline value |
|---|---:|
| v2 registry properties | 34 |
| v2 applicability predicates | 32 |
| v2 property categories | 22 |
| Agentic risk families | **10** |
| Assessment profiles | 5 named + 1 MCP baseline = 6 files |
| `AGENT.RAG.*` properties | **0** |
| Workspace crates | 15 |
| CLI subcommands | 10 |
| CI jobs | 14 |

Existing profiles, none of which may change:

- `mcp-security-baseline.json`
- `agentic-security-baseline-2026.json` — 10 properties
- `prompt-injection-baseline-2026.json` — 3 properties
- `tool-security-baseline-2026.json` — 6 properties
- `identity-security-baseline-2026.json` — 6 properties
- `memory-security-baseline-2026.json` — 6 properties

The ten Agentic risk families, which must still be exactly ten at the end:

`AgentGoalHijacking`, `ToolMisuseExploitation`, `IdentityPrivilegeAbuse`,
`AgenticSupplyChain`, `UnexpectedCodeExecution`, `MemoryContextPoisoning`,
`InsecureInterAgentCommunication`, `CascadingFailures`,
`HumanAgentTrustExploitation`, `RogueAgents`.

## 3. A constraint discovered while freezing the baseline

`DESIGN.md` §3 and `EVALUATION.md` both state that RAG properties may sit
outside the ten Agentic risk families "because `risk_family` is optional in
coverage v2". That is true of the **JSON Schema**: `risk_family` is not in the
`required` list.

It is *not* true of the **Rust validator**. `crates/dare-coverage/src/property.rs`
carries an additional rule:

```rust
if prop.id.starts_with("AGENT.") && prop.risk_family.is_none() {
    return Err(/* "AGENT property requires risk_family" */);
}
```

So an `AGENT.RAG.*` property with no family — exactly what the design calls for —
would be rejected by the registry loader as it stands today.

The three options and why one of them is right:

1. **Give the RAG properties an existing family.** This contradicts the design
   intent directly, and it is not cosmetic: `derive_risk_family_coverage` counts
   properties per family, so folding six RAG properties into (say)
   `MemoryContextPoisoning` would take that family's property count from 1 to 7
   and break the Cycle 012 regression that asserts `*.properties=1` across ten
   families. Rejected.
2. **Add an eleventh family.** Explicitly forbidden by the approval. Rejected.
3. **Scope the validator rule to exclude the RAG namespace.** Every `AGENT.*`
   property still requires a family *except* `AGENT.RAG.*`, which the design
   places outside the Agentic taxonomy on purpose.

Option 3 is what this cycle implements. It is a minimal, namespace-scoped
relaxation that leaves every existing property's family untouched and keeps the
rule in force for every future non-RAG `AGENT.*` property. It is recorded here
rather than made silently, and is pinned by tests asserting that a non-RAG
`AGENT.*` property with no family is *still* rejected.

The corresponding fact on the reporting side is already favourable:
`derive_risk_family_coverage` skips any property whose `risk_family` is `None`,
so RAG properties never enter the Agentic family view at all. The family count
stays at ten because the RAG properties are not in that taxonomy, not because
anything was hidden.

## 4. Inherited contracts that must not move

| Contract | Owner cycle | Obligation for Cycle 017 |
|---|---|---|
| Verdict vocabulary, evidence records, `validate_secret_safety` | 001 | reuse; define no second contract |
| Budgets, kill switch, `SYNTHETIC_NOOP`, zero state change / egress | 009 | reuse for `LOCAL_SYNTHETIC` |
| Coverage denominator mathematics | 006 | unchanged |
| Ten Agentic risk families | 012 | unchanged, and no eleventh |
| Untrusted-content instruction boundary | 013 | reuse concepts; Cycle 013 stays the final judge |
| Tool poisoning / misuse semantics | 014 | untouched |
| `PrincipalKind`, principal and tenant semantics | 015 | re-export, never redefine |
| Persisted-memory semantics | 016 | keep separate; retrieved content is not memory |

## 5. Predicted movement

What Cycle 017 is expected to change, so that anything else showing up in the
diff is a signal rather than noise:

- `+6` v2 registry properties (`AGENT.RAG.*`), all with `risk_family: None`
- `+5` applicability predicates (`retrieval_trace_present`,
  `retrieval_policy_present`, `document_acl_present`,
  `retrieval_provenance_present`, `retrieval_tenant_context_present`)
- `+1` profile (`rag-security-baseline-2026`)
- `+1` crate (`dare-rag-security`)
- `+1` CLI subcommand (`validate rag-security`)
- `+1` CI job (`rag-security-2026`)
- one namespace-scoped relaxation of the `AGENT.*` risk-family rule (§3)
- **no** change to any existing property, profile, family or denominator

## 6. Lessons carried in from Cycle 016

Recorded because each one cost something to learn:

1. **A refusal is a persistence surface.** Cycle 016 shipped a validator that
   quoted the offending value, so refusing a URL printed the endpoint into the
   log line the refusal existed to prevent. Sweep hostile values *before* the
   schema validator sees them, and name the object rather than the value.
2. **Test the behaviour against the invariant it bears on.** Two Cycle 016 tests
   staged one violation while judging an unrelated invariant; they passed and
   proved nothing.
3. **Adapters must not assert facts they cannot know.** A trace that could carry
   full document records could assert a cross-tenant item belonged to the acting
   tenant. Traces name objects by id; the declared corpus supplies the bindings.
4. **PASS on silence is the default failure mode.** Every invariant needs a
   positive coverage contract, and the ones about what something *did* need an
   exercise channel, not merely a presence channel.
5. **Write the generators, not the fixtures.** Hand-edited corpora drift.
   Generators with `--check` make drift a CI failure.
6. **Run the real CI job locally.** Cycle 013 shipped a broken gate that a
   hand-written equivalent would not have caught.
7. **A disclaimer has to stay writable.** An over-eager claim detector that
   cannot express "this is not a certification" makes the honest sentence
   impossible to write.

## 7. Residual risks inherited, not introduced

- The corpus of every validation cycle is finite; a technique nobody wrote a
  vector for produces no finding.
- Observations are staged or replayed from synthetic sources and describe a
  reference implementation, never a production one.
- `cargo audit` reports one allowed warning at baseline: an unmaintained
  transitive dependency of `reqwest`, reachable only through MCP discovery.
