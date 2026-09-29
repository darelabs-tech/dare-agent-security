# Cycle 025 — Design: Runtime OpenTelemetry Security

**Version:** v0.2 | **Date:** 2026-09-29 | **Status:** DESIGN APPROVED  
**Base branch:** `main` (`00e7aff`, Cycles 001–024 merged, PR #49)  
**Proposed crate:** `crates/dare-runtime-telemetry` (Q1)  
**Also touched:** the CLI gains one subcommand. The coverage registry and the profiles
gain additive entries only (Q4). `dare-attack-path` gains one projector if Q6 (a) is
chosen. Engine crates 013–022 and the Cycle 023/024 outputs for existing inputs stay
unchanged.  
**Approval:** APPROVED (Design phase) 2026-09-29 — see `APPROVAL.md`. Execution is not yet authorized.

---

## 1. Description

Cycles 013–022 judge an agent by **driving** it: a scenario, a replayed capture, a
simulated reference agent, or an authorized remote run. Cycles 023–024 then join those
verdicts into paths and blast radius. What none of them looks at is what the agent
**actually did in production**, as its own runtime telemetry records it. Agent frameworks
increasingly emit OpenTelemetry traces that follow the GenAI semantic conventions: one
span per agent invocation, model call and tool execution, with the agent, the tool, the
operation and often the prompt content as attributes.

Cycle 025 adds **runtime OpenTelemetry security analysis**. It reads **OTLP trace
exports supplied as local files**, together with a **runtime policy** that states what
the deployment allows. It then judges two things:

1. **Runtime behaviour, observed:** did the traced run stay inside its policy?
   - Every tool executed must be one the acting agent may call.
   - A destructive tool must follow a recorded human approval.
   - The principal must stay the one the run started under.
   - No tenant's data may be touched from another tenant's run.
   - No outbound call may reach an undeclared host.
   - No operation may be retried beyond its bound.

   These are verdicts on **existing** properties (`AGENT.TOOL.AUTHORIZATION_BOUNDARY`,
   `AGENT.HUMAN_APPROVAL.INTENT_BINDING`, …), backed by `TRACE` evidence. The registry
   already accepts that evidence class and no engine produces it yet.
2. **The telemetry itself, as an attack surface:**
   - Does the trace carry secrets, bearer tokens or raw prompt and completion content it
     should not carry?
   - Is it complete enough that an absent span means an absent action (sampling, dropped
     attributes, orphan spans)?

A trace is **self-reported by the system under test**. OpenTelemetry signs nothing, and
a span that is absent can be one that was sampled out. The central rule of this cycle is
therefore the Cycle 018 one, applied to telemetry: **no PASS from absence.**
- A PASS needs positive evidence in a trace proven complete for the property.
- A violation observed in any span is a FAIL.
- Everything else is INCONCLUSIVE, with the reason stated.

The tool never emits telemetry, never opens a collector port and never calls the
system under test. It reads files and writes files.

---

## 2. Objectives and success metrics

| # | Objective | Metric | Target |
|---|-----------|--------|--------|
| O-01 | Detect runtime violations | OTEL-LAB attack entries whose violation is visible in the trace that the engine reports FAIL, with the deciding span cited | 100 % |
| O-02 | No PASS from absence | Entries where the trace is sampled, truncated, orphaned or missing the spans a property needs, and the engine still reports PASS | 0 |
| O-03 | Controls stay green | OTEL-LAB control entries (policy-conformant, complete traces) reported PASS | 100 % |
| O-04 | No secret leaves through the tool | Artifacts carrying any attribute value, prompt text or credential shape from the input trace (only keys, span ids and digests are written) | 0 |
| O-05 | Telemetry hygiene detected | Hygiene attack entries (secrets, bearer tokens, raw prompt/completion content, PII markers in attributes) reported FAIL on the telemetry-confidentiality property | 100 % |
| O-06 | Determinism | Same trace files (in any order) and same policy give byte-identical outputs | 10/10 runs |
| O-07 | Compatibility | Existing property IDs, profile denominators, Cycle 009–024 suites and Cycle 023/024 outputs for existing inputs unchanged | 0 regressions |
| O-08 | Boundedness | 100 000 spans across 64 files analysed in release | < 10 s, no bound overshoot |

---

## 3. Stakeholders

| Role | Name / team | Main interest |
|------|-------------|---------------|
| Product Owner | DARE Labs | Scope, approval, the "analysis only, no telemetry" product rule |
| Tech Lead | DARE Agent Security maintainers | One verdict system, existing properties reused, no OTel SDK dependency |
| Platform / SRE teams | Customer | Their existing traces become security evidence without new instrumentation |
| AppSec | Primary users | Which runtime runs broke policy, with the span that shows it |
| Privacy / compliance | Customer | Whether their telemetry pipeline itself leaks prompts, tokens or PII |
| Security reviewers | DARE Review | No PASS from missing spans; no attribute value ever copied out |

---

## 4. Functional requirements

| ID | Requirement | Priority | Acceptance criterion |
|----|-------------|----------|----------------------|
| RF-01 | Trace input | MUST | Reads 1–64 OTLP/JSON trace export files (`ExportTraceServiceRequest` JSON mapping: `resourceSpans` → `scopeSpans` → `spans`). Each file is admitted by size, depth and schema before parsing. Spans are normalized: ids validated as hex of the right length, times as integers, attributes as typed values. A malformed file is refused (exit 3) and nothing is written |
| RF-02 | Semantic conventions | MUST | A closed, versioned mapping (§4.2) recognizes the GenAI and related conventions the engine relies on: agent invocation, model call, tool execution, MCP call, HTTP client call, and human-approval events. The pinned convention version is recorded in every result. A span that matches none is kept and counted, never guessed |
| RF-03 | Runtime policy | MUST | A new closed schema, `schemas/runtime-telemetry/v1/runtime-policy.schema.json`, states per agent: allowed tools, destructive tools that need approval, the expected principal, the tenant, allowed egress hosts, and the retry bound. The policy is digest-bound into the result. Without a policy, only the telemetry properties (RF-07, RF-08) are judged, and the behaviour properties are NOT_APPLICABLE with that reason (Q3) |
| RF-04 | Trace reconstruction | MUST | Spans are grouped by trace id and linked by parent id into trees. Orphan spans (missing parent), duplicate span ids, cycles and cross-file duplicates are detected and reported. Ordering uses span ids and start times only, never file order |
| RF-05 | Completeness signals | MUST | Per trace: sampled flag, `dropped_attributes_count`, `dropped_events_count`, `dropped_links_count`, orphans, and spans whose required attributes are missing. A property whose required spans are not proven complete is INCONCLUSIVE with the reason (O-02) |
| RF-06 | Behaviour properties | MUST | Six evaluators (§4.1 B-1..B-6) over each trace: tool authorization, approval before a destructive tool, principal continuity, tenant boundary, egress boundary, retry bound. Each maps to an **existing** property and emits `TRACE` evidence citing trace id and span ids |
| RF-07 | Telemetry confidentiality | MUST | Attribute values are scanned with the product's credential markers and bearer-token rule, plus the GenAI content attributes (prompt, completion, system instructions, tool arguments and results) when the policy says content capture is not allowed. Only the key, the span id and a digest are reported; the value is never copied |
| RF-08 | Telemetry completeness | MUST | A property states whether the security-relevant operations the policy names (tool calls, approvals, egress) are observable in the supplied traces. The engine reports PASS only with positive evidence that every required operation kind appears with its required attributes |
| RF-09 | Property registry | MUST | Behaviour verdicts reuse existing properties. Telemetry confidentiality and completeness need two new properties in a new family (Q4 — e.g. `AGENT.TELEMETRY.CONFIDENTIALITY`, `AGENT.TELEMETRY.COMPLETENESS`), gated by a new predicate `runtime_trace_present`. Existing IDs and denominators are unchanged |
| RF-10 | Modes | MUST | `REPLAY` (supplied trace files) and `SIMULATED` (deterministic reference agents that write OTLP/JSON traces in-process for the lab). No live receiver (Q2) |
| RF-11 | OTEL-LAB corpus | MUST | ≥ 40 entries (§4.4), each a trace set plus a policy. Every attack class has a control twin. Fixtures store the class and the evidence, never the expected verdict |
| RF-12 | Hostile corpus | MUST | Bounded fixtures for oversize files, deep nesting, span floods, id collisions, parent cycles, bidi/control characters in names, secrets in attribute values, and non-UTF-8 content. Each is refused or neutralized, and no value is echoed |
| RF-13 | CLI | MUST | `dare-agent-security validate runtime-telemetry --traces <file>… [--policy <file>] --output-dir <dir>` with lower-only bounds and `--json`. Exit codes follow the engines: 0 all PASS or NOT_APPLICABLE, 2 any FAIL or INCONCLUSIVE, 3 refusal, 1 internal |
| RF-14 | Artifacts | MUST | `runtime-telemetry-result.json`, `runtime-telemetry-evidence.json`, `runtime-telemetry-findings.json` and `summary.md`. Each passes the output secret sweep before the first write |
| RF-15 | Attack-graph projection | SHOULD | A Cycle 023 projector for this engine's result (Q6): observed tool calls, delegations and egress become `OBSERVED` edges with `TRACE` evidence, and behaviour verdicts become guards. Existing ATTACK-PATH-LAB outputs stay byte-identical |
| RF-16 | Coverage and profile | SHOULD | Results feed Cycle 006 coverage. A new optional profile `runtime-telemetry-baseline-2026` (Q5), with the eleven existing denominators unchanged |
| RF-17 | Product integration | COULD | The product fixture may name trace files for an assessment run (Q7) |

### 4.1 Behaviour evaluators (the Blueprint fixes the exact span/attribute rules)

| # | Evaluator | Existing property | FAIL when | PASS needs |
|---|-----------|-------------------|-----------|------------|
| B-1 | Tool authorization | `AGENT.TOOL.AUTHORIZATION_BOUNDARY` | a tool-execution span names a tool that is not in the acting agent's allowed set | every tool span attributed to an agent, all allowed, trace complete |
| B-2 | Approval before destructive tool | `AGENT.HUMAN_APPROVAL.INTENT_BINDING` | a destructive tool executes with no approval event for it earlier in the same trace | an approval precedes every destructive call and names the same tool |
| B-3 | Principal continuity | `AGENT.IDENTITY.PRINCIPAL_BINDING` | a span in the trace runs under a principal other than the trace's root principal, with no delegation span between | the principal attribute is present on every agent/tool span and constant, or changed only by a recorded delegation |
| B-4 | Tenant boundary | `AGENT.MEMORY.TENANT_BOUNDARY` / `AGENT.RAG.TENANT_DOCUMENT_ISOLATION` | a retrieval or memory span touches a resource of another tenant than the run's | every such span carries a tenant and it matches |
| B-5 | Egress boundary | `AGENT.CODE_EXECUTION.EGRESS_BOUNDARY` | an HTTP-client span inside the agent's trace targets a host outside the allowed list | every client span carries its host, and every host is allowed |
| B-6 | Retry bound | `AGENT.FAILURE.RETRY_AMPLIFICATION` | the same operation on the same target is retried more times than the bound within one trace | retries are counted from complete traces and stay within the bound |

### 4.2 Recognized span kinds (closed)

- Agent invocation;
- model call;
- tool execution;
- MCP client/server call;
- HTTP client call;
- human-approval event;
- delegation.

The mapping names the exact attribute keys (for example `gen_ai.operation.name`,
`gen_ai.agent.name`, `gen_ai.tool.name`, `server.address`). It is fixed and versioned in
the Blueprint, against one pinned version of the OpenTelemetry semantic conventions. The
GenAI conventions are still marked *Development* upstream, so a key the mapping does not
know is never guessed: the span is counted as unrecognized.

### 4.3 Hard maxima (input may only lower them)

| Bound | Maximum |
|---|---|
| Trace files | 64 |
| File size | 16 MiB each, 256 MiB in total |
| JSON depth | 64 |
| Spans in total | 1 000 000 |
| Attributes per span | 256 |
| Attribute value length examined | 64 KiB (longer values are digested, never scanned beyond the bound) |
| Tree depth | 256 |

### 4.4 OTEL-LAB (at least 40 entries)

Every class has attack entries and control twins:
- **B-1 … B-6:** each has at least one FAIL entry and one PASS control.
- **Completeness:** sampled-out spans, dropped attributes, orphan subtrees and a missing
  principal attribute. Each must give INCONCLUSIVE, never PASS (O-02).
- **Confidentiality:** a bearer token in an attribute, a credential marker, prompt and
  completion content under a policy forbidding it, and a PII marker. Each has a clean
  control.
- **Multi-file:** one trace split across files, and duplicated spans across files.
- **Hostile:** the RF-12 fixtures.

---

## 5. Non-functional requirements

| ID | Category | Requirement | Target |
|----|----------|-------------|--------|
| RNF-01 | Determinism | Same inputs in any file order → byte-identical outputs; ordering on ids and times only | 10/10 |
| RNF-02 | Boundedness | §4.3 maxima enforced before the step that would exceed them | 0 overshoot |
| RNF-03 | Performance | O-08; the full OTEL-LAB in CI | < 10 s release; < 60 s lab |
| RNF-04 | Containment | The crate depends on no network crate and on no OpenTelemetry SDK or collector crate. Only the CLI depends on it. A manifest test enforces both | enforced |
| RNF-05 | Explainability | Every FAIL and INCONCLUSIVE cites trace id, span ids and the rule; every PASS cites the spans that prove it | 100 % |
| RNF-06 | Quality gate | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`, `cargo audit` | All green |

---

## 6. Security requirements

| ID | Requirement | Reference |
|----|-------------|-----------|
| RS-01 | Traces and the policy are untrusted input: schema-validated, size-, depth- and count-bounded before use (§4.3) | OWASP A03 |
| RS-02 | **No value leaves:** artifacts carry attribute keys, span ids, rule ids and digests, never an attribute value, prompt, completion or tool argument. Every artifact passes the output secret sweep. Error messages name positions, never content | OWASP A02 |
| RS-03 | No file read outside the supplied paths; no symlink followed; no URL in a trace is dereferenced | OWASP A01 |
| RS-04 | No new third-party dependency (OTLP/JSON parsed with the existing serde stack); `cargo audit` clean | OWASP A06 |
| RS-05 | Secrets: none read or needed; no environment variable changes behaviour; OTel exporter environment variables are ignored | — |
| RS-06 | **No PASS from absence:** PASS needs positive evidence in a trace proven complete for the property; missing or sampled spans give INCONCLUSIVE (O-02) | Cycle 018 aggregation |
| RS-07 | **Self-reported evidence is labelled so:** every verdict from a trace records that the evidence is self-reported by the system under test and unsigned | Product evidence model |
| RS-08 | **No telemetry, analysis only:** the tool emits no telemetry, opens no port, contacts no collector and does not execute or call the system under test | Product Design §10 |
| RS-09 | Hostile names (bidi, control characters, markup) are neutralized in `summary.md` and never rendered raw | Cycle 021 RF-12 |

---

## 7. Technical stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Rust | edition 2021, MSRV 1.88 |
| Serialization / schema | serde, serde_json, jsonschema | workspace |
| Digests | sha2 | workspace |
| Evidence and verdicts | `dare-security-evidence`, the Cycle 018 aggregation | workspace |
| Semantic conventions | OpenTelemetry semantic conventions (GenAI, HTTP, MCP) | one pinned version, [to be fixed in the Blueprint] |
| New dependencies | None | — |

---

## 8. External integrations

None at runtime. The tool reads OTLP/JSON files that the user exported from their own
pipeline, for example with the OpenTelemetry Collector file exporter. It does not
receive, forward or emit telemetry, and it calls no model provider.

---

## 9. Constraints

- **Timeline:** one cycle, Design → Blueprint → Review → Execute.
- **Infrastructure:** GitHub Actions only. The PR-open-only trigger is preserved, and a
  new CI job, `runtime-telemetry-2026`, runs the lab.
- **Technical:**
  - an additive crate;
  - no `unwrap()` in production;
  - engines 013–022 unchanged;
  - Cycle 023/024 outputs for existing inputs byte-identical;
  - additive registry and profile changes only.
- **Compliance:** lab traces are synthetic. Users' traces never leave their machine, and
  no attribute value is ever copied into an artifact.

---

## 10. Out of scope (v1)

- **Live collection:** no OTLP receiver (gRPC or HTTP), no collector plugin, no
  streaming. The tool reads files only (Q2).
- **OTLP protobuf:** only the OTLP/JSON encoding is read. Binary protobuf needs a
  generated-code dependency, and the Collector can write JSON.
- **Metrics and logs signals:** traces only. Logs may come in a later cycle.
- **Anomaly detection or ML baselines:** every verdict is a fixed rule against the
  policy. There is no learned "normal".
- **Trace authenticity:** OpenTelemetry has no signatures, so the engine cannot prove a
  trace was not edited. It binds the result to the files' digests and states that the
  evidence is self-reported (RS-07).
- **Instrumenting the agent:** the tool never adds or changes instrumentation. Users
  supply what their framework emits.
- **Enforcement:** no blocking, alerting or runtime intervention. This is analysis, not
  a runtime guard.
- **Scores:** no risk score, probability or weighting.

---

## 11. Risks and mitigations

| # | Risk | Probability | Impact | Mitigation |
|---|------|-------------|--------|------------|
| R-01 | PASS read from a trace missing the violating span (sampling, dropped attributes, partial export) | High | High | RS-06: PASS only on traces proven complete for the property; every completeness gap gives INCONCLUSIVE with its reason; O-02 attack entries per gap |
| R-02 | The engine republishes the secrets or prompts it found | Medium | High | RS-02: keys, span ids and digests only; the output sweep before every write; O-04 checked over the whole lab |
| R-03 | GenAI semantic conventions change (they are *Development* upstream) | High | Medium | One pinned convention version, recorded in each result; unknown keys counted, never guessed; the mapping is a versioned table the next cycle can extend |
| R-04 | Frameworks use different attribute keys for the same fact (principal, tenant) | High | Medium | The policy may name the attribute keys to read for principal and tenant (closed, bounded list); without them B-3/B-4 are INCONCLUSIVE, not guessed |
| R-05 | A doctored trace passes | Medium | Medium | Digest binding, structural checks (orphans, cycles, duplicate ids, time order) and the self-reported label; authenticity stays out of scope and is stated in the summary |
| R-06 | Very large exports | Medium | Medium | §4.3 maxima, streaming-free but bounded parsing, refusal before allocation beyond the bound |

---

## 12. Compatibility

Cycle 025 must prove that it:

1. leaves every existing property ID and the eleven profile denominators unchanged
   (additive registry entries only);
2. leaves engines 013–022 and their artifacts unchanged;
3. leaves `validate attack-paths` and `validate blast-radius` outputs byte-identical for
   every existing input, including the 156 Cycle 023 goldens and the BRL lab, even if the
   RF-15 projector is added;
4. keeps `dare-adversarial` eligibility and `dare-continuous` drift unchanged;
5. keeps the PR-open-only CI trigger, with no network access and no secrets.

**Completion rule:** every acceptance criterion maps to executed evidence in `PROOF.md`,
and defects are recorded in `REGRESSION.md`.

---

## 13. Open questions for Review

All answered by the Product Owner on 2026-09-29 (the recommended option in each case):
Q1 (a), Q2 (a), Q3 (a), Q4 (a), Q5 (a), Q6 (a), Q7 (b). RF-15 therefore stays SHOULD, and
RF-17 is out of scope for v1.

1. **Crate.**
   - **(a) Recommended:** a new engine crate, `dare-runtime-telemetry`, with the same
     result/evidence shape as engines 013–022.
   - **(b)** A module in `dare-remote-validation`. That mixes observation of production
     with authorized active testing.
2. **Input.**
   - **(a) Recommended:** OTLP/JSON files only.
   - **(b)** Also a localhost-only OTLP/HTTP receiver. That opens a port, and it breaks
     the "no telemetry, no listener" rule the product has kept since Cycle 022.
3. **Policy.**
   - **(a) Recommended:** a new small runtime-policy schema (RF-03). Without a policy,
     only the telemetry properties are judged.
   - **(b)** Reuse the Cycle 023 system model and extend it with allowed tools and hosts.
     This changes a Cycle 023 schema.
4. **Registry.**
   - **(a) Recommended:** behaviour verdicts on existing properties, plus two new
     properties in a new `AGENT.TELEMETRY` family, gated by `runtime_trace_present`.
   - **(b)** No new properties. Telemetry hygiene is then reported as findings without
     a property verdict.
5. **Profile.**
   - **(a) Recommended:** a new optional profile, `runtime-telemetry-baseline-2026`.
   - **(b)** No profile in v1.
6. **Attack-graph projection (RF-15).** Cycles 023 and 024 reserved "edges and reach from
   live traces" for this cycle.
   - **(a) Recommended:** SHOULD. Add a Cycle 023 projector for this engine's result,
     with existing outputs byte-identical.
   - **(b)** MUST.
   - **(c)** Out of scope for v1.
7. **Product integration (RF-17).**
   - **(a)** COULD: the product fixture names trace files.
   - **(b) Recommended:** out of scope for v1. The product's report layout for runtime
     evidence is better decided once the engine's output is stable.

---

## 14. Approval checklist

- [x] Functional requirements reviewed and prioritized
- [x] "Files only, analysis only, no telemetry emitted" architecture accepted
- [x] The no-PASS-from-absence rule (RS-06) and the completeness signals (RF-05) accepted
- [x] "No attribute value ever leaves" (RS-02) accepted
- [x] Behaviour evaluators B-1..B-6 and their existing properties accepted
- [x] Hard maxima (§4.3) accepted
- [x] OTEL-LAB classes (§4.4) accepted
- [x] Open questions Q1–Q7 answered
- [x] Critical risks (R-01, R-02) have accepted mitigations
