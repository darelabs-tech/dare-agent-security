# Cycle 024 — Design: Blast-Radius Analysis

**Version:** v0.1 | **Date:** 2026-09-28 | **Status:** DRAFT — awaiting Review  
**Base branch:** `main` (`d125081`, Cycles 001–023 merged, PR #48)  
**Proposed crate:** `crates/dare-blast-radius` (Q1)  
**Also touched:** `crates/dare-attack-graph`, which gains the continuity rule, moved from
`dare-attack-path` without a behaviour change (Q1). The CLI gains one subcommand.
Engine crates 013–022 stay unchanged.  
**Approval:** not yet approved. Execution is not authorized.

---

## 1. Description

Cycle 023 answers a question that starts from the **outside**: from which entry points
can an attacker reach which targets, and did the controls on each path hold? The
reserved scope of Cycle 024 asks the opposite question. It starts from **one thing
already lost**:

> If this node is compromised (a principal taken over, a credential leaked, a document or
> channel injected, a tool or component tampered with), what else can the attacker reach
> from it? Through which relationships, and which observed controls stand in the way?

This is the question an incident responder asks after a leak, and that an architect asks
before granting an agent a credential. A single engine cannot answer it, because the
answer crosses engines. A path list from Cycle 023 does not answer it either: it
enumerates entry → target pairs, not everything reachable from one seed. It also cannot
tell apart a target that is reachable only **through** a control that held from one
reachable **around** every control.

Cycle 024 adds **blast-radius analysis** over the Cycle 023 v2 attack graph:

1. **Input:** a validated v2 `attack-graph.json`, as written by `validate attack-paths`,
   and a **compromise scenario**. The scenario is a small, closed document naming 1 to
   64 seeds, each with a compromise kind.
2. **Reach:** from each seed, a bounded, deterministic search follows the graph. It
   obeys the same authority-continuity rules (C1–C6) that decide feasibility in Cycle
   023, so an attacker's reach never includes a step that no acquired authority
   explains.
3. **Two views of the same reach:**
   - **structural reach** follows every feasible relationship;
   - **uncontained reach** additionally refuses to cross an edge whose guarding controls
     were all observed to hold (`PASS`).

   A node in the first view but not the second is **contained**: it is reachable only
   across a control that held. The held edges that do the containing form the
   **containment frontier**.
4. **Impact is reported as facts, not a score:**
   - reachable targets by class (sensitive resource, privileged credential, destructive
     capability, other tenant's resource, external publication);
   - tenants reached, and trust boundaries crossed;
   - for each reached target, one shortest witness route with its control state (the
     Cycle 023 rule).

It does **not** compute a probability, a likelihood or a risk score. It does not execute
anything, and it does not claim that an unreached node is safe: reach is bounded by what
the artifacts and the system model state.

---

## 2. Objectives and success metrics

| # | Objective | Verifiable metric | Target |
|---|-----------|-------------------|--------|
| O-01 | Reach from real evidence | BLAST-RADIUS-LAB scenarios whose graph comes from `validate attack-paths` over real engine runs, with no hand-written graph | 100 % |
| O-02 | Reach recall on ground truth | Expected reachable targets (per seed, per view) in BLAST-RADIUS-LAB that are reported | 100 % |
| O-03 | No false containment | Nodes reported `CONTAINED` that are reachable by a route with no edge whose guards all `PASS` | 0 |
| O-04 | No invented reach | Reported reachable nodes whose witness route breaks a continuity rule (C1–C6) or uses an edge absent from the graph | 0 |
| O-05 | Honest truncation | Runs that hit a bound and do not report `truncated: true`, the bound that fired, and the seeds left unexhausted | 0 |
| O-06 | Determinism | The same graph and scenario give byte-identical output | 10/10 runs |
| O-07 | Compatibility | Cycle 023 lab, CLI and outputs unchanged after the continuity rule moves (Q1); v1 goldens; registry and profiles | byte-identical |
| O-08 | Boundedness | Largest lab graph (≥ 2 000 nodes, ≥ 10 000 edges) with 64 seeds, both views | < 10 s in release, no bound overshoot |

---

## 3. Stakeholders

| Role | Name / team | Main interest |
|------|-------------|---------------|
| Product Owner | DARE Labs | Scope, approval, and the boundary with Cycles 023 and 025 |
| Tech Lead | DARE Agent Security maintainers | One continuity rule for paths and reach, one graph contract, no second verdict system |
| Incident responders | Primary users | "This credential leaked: what can it touch, and what stopped it?" |
| Architects / platform owners | Customer | The reach of an agent or credential before it is granted, and which control contains it |
| AppSec | Primary users | Which failed control widens the blast radius most, as counts they can act on |
| Security reviewers | DARE Review | Containment never claimed without a held control on every route; no score dressed as a fact |

---

## 4. Functional requirements

| ID | Requirement | Priority | Acceptance criterion |
|----|-------------|----------|----------------------|
| RF-01 | Graph input | MUST | The analysis reads a v2 `attack-graph.json` and admits it by size, depth and schema, then `dare_attack_graph::v2::validate_graph_v2`. An invalid graph is refused (exit 3) and nothing is written. The graph is never rebuilt or re-judged |
| RF-02 | Compromise scenario | MUST | A new schema, `schemas/blast-radius/v1/compromise.schema.json` (§4.1), names 1–64 seeds by `node_id`, or by `entity_id` when the graph came from a system model. Each seed has a kind. A seed that resolves to no node, a kind that does not fit the node's type, or a duplicate seed is refused |
| RF-03 | Seed from entry points | SHOULD | Instead of a scenario, `--seed-entry-points` uses every entry point of the graph as a seed, each with the kind its entry class implies (§4.2). This answers "from anywhere an attacker starts" |
| RF-04 | Compromise kinds | MUST | The closed set `PRINCIPAL_TAKEOVER`, `CREDENTIAL_LEAK`, `CONTENT_INJECTION`, `COMPONENT_COMPROMISE` sets the initial authority state, in a table fixed by the Blueprint (§4.2) |
| RF-05 | Continuity-respecting reach | MUST | Every reported reach step satisfies rules C1–C6 of Cycle 023 §7.3, using the same code (Q1). A step no rule explains is not taken. The count of steps refused this way is reported per seed |
| RF-06 | Two views | MUST | Structural reach uses every edge. Uncontained reach refuses an edge whose control is `Decided(PASS)` (every guard `PASS`); structural edges (BQ-1 of Cycle 023) stay traversable in both views. Each reached node is `EXPOSED` (in both views) or `CONTAINED` (structural only) |
| RF-07 | Witness routes | MUST | For each reached target, and each seed, one shortest witness route per view is reported. It gives its edges, its control state under the Cycle 023 rule, and its failed guards. Shortest means fewest edges, with ties broken by path id |
| RF-08 | Containment frontier | MUST | For each `CONTAINED` target: the held edges that its shortest structural route crosses, with their properties and evidence ids. Across a seed: the set of held edges that separate structural reach from uncontained reach. Reported as counts over reached nodes, not a score |
| RF-09 | Impact facts | MUST | Per seed and in total, split by view: reached targets by target class; tenants reached other than the seed's; trust boundaries crossed; privileged credentials acquired on the way (which widen later steps through C2). No weighting, no aggregate number beyond counts |
| RF-10 | Remediation delta | SHOULD | For each edge that is `CONTROL_FAILED` on some uncontained witness route: how many `EXPOSED` targets would become `CONTAINED` if that edge's controls held. Computed by re-running the uncontained view with that one edge treated as held, bounded to the 64 such edges nearest the seeds. Counts only (Q5) |
| RF-11 | Artifacts | MUST | `blast-radius.json` (schema `schemas/blast-radius/v1/blast-radius.schema.json`), `summary.md`, and `graph.mmd` / `graph.dot` views that mark seeds, reach and containment in text. Every artifact passes the Cycle 023 output sweep before any file is written |
| RF-12 | CLI | MUST | `dare-agent-security validate blast-radius --graph <file> (--compromise <file> \| --seed-entry-points) --output-dir <dir>` with lower-only bounds. Exit 0 when no target is `EXPOSED` and nothing was truncated; 2 when a target is `EXPOSED` or the search was truncated; 3 on refusal; 1 on internal error |
| RF-13 | BLAST-RADIUS-LAB | MUST | At least 20 scenarios, each built from a real ATTACK-PATH-LAB graph (§4.4) plus a compromise scenario, with expected reach per view, containment and exit code. Every class has a control twin in which one guarding control holds and a target moves from `EXPOSED` to `CONTAINED` |
| RF-14 | Product integration | COULD | A product fixture may name `blast_radius: <path>`. The product reads it, validates it against the schema, and adds its counts to the technical report. It never runs the analysis itself (Q6) |
| RF-15 | Shared continuity rule | MUST | The continuity function moves to `dare_attack_graph::v2` and `dare-attack-path` calls it there. Cycle 023's lab, CLI tests and outputs stay byte-identical (Q1, O-07) |

### 4.1 Compromise scenario (fields)

- `schema_version`: `"1"`.
- `scenario_id`.
- `graph_id`: the graph it was written for. A mismatch is refused, so a scenario cannot be
  applied to a different graph by accident.
- `seeds[]`: `{ node_id | entity_id, kind, note? }`.
- Optional lower bounds: `max_depth` and `max_states`.

Closed schema, `additionalProperties: false`, and every string label-checked.

### 4.2 Initial authority by kind (the Blueprint fixes the table)

| Kind | Fits node types | Initial state |
|---|---|---|
| `PRINCIPAL_TAKEOVER` | HUMAN, AGENT, IDENTITY | P = seed, A = {seed} |
| `CREDENTIAL_LEAK` | CREDENTIAL | P = seed, A = {seed}: the attacker acts as the credential |
| `CONTENT_INJECTION` | DATA, and the channel nodes of 013/021 | P unset; the first `TRANSFERS_TO` into an actor makes that actor act (C5) |
| `COMPONENT_COMPROMISE` | TOOL, MCP_SERVER, CAPABILITY, DOWNSTREAM_SERVICE | P unset, A = {seed}: the component acts under whatever authority its edges carry |

`--seed-entry-points` maps entry classes onto kinds:
- `LOW_PRIVILEGE_PRINCIPAL` and `PEER_AGENT` → principal takeover;
- untrusted input, external content, retrieved document and memory write → content
  injection;
- `SUPPLY_CHAIN_COMPONENT` → component compromise.

### 4.3 Hard maxima (input may only lower them)

| Maximum | Value |
|---|---|
| Graph file | 16 MiB, depth 64, the Cycle 008 node and edge maxima (10 000 / 50 000) |
| Seeds | 64 |
| Route depth | 12 edges (default 8), as in Cycle 023 |
| Search states per seed | 1 000 000; total 5 000 000 |
| Remediation-delta edges | 64 |

### 4.4 BLAST-RADIUS-LAB (at least 20 scenarios)

The graphs are the ones the ATTACK-PATH-LAB already builds from real engine runs. No
graph is written by hand. Classes:

| Range | Class |
|---|---|
| 001–004 | Leaked privileged credential → resources and other tenants it reaches (015, 018) |
| 005–008 | Taken-over low-privilege principal → delegation → service identity → credential (015, 020) |
| 009–011 | Injected retrieved document or memory item → acting principal → what that principal reaches (016, 017) |
| 012–014 | Compromised package or tool → assistant → destructive capability (013, 019, 021) |
| 015–016 | Containment: the same seed with one guarding control `PASS` → targets move to `CONTAINED`, frontier named |
| 017–018 | Continuity: a reach step under a principal never acquired is refused, and counted |
| 019 | `--seed-entry-points` over a multi-engine graph |
| 020 | Truncation: a dense graph hits `max_states`, reported |
| + | Every attack class has a control twin |

---

## 5. Non-functional requirements

| ID | Category | Requirement | Target |
|----|----------|-------------|--------|
| RNF-01 | Determinism | Same inputs → byte-identical outputs; ordering on ids only | 10/10 |
| RNF-02 | Boundedness | §4.3 maxima enforced before the step that would exceed them | 0 overshoot |
| RNF-03 | Performance | Full BLAST-RADIUS-LAB in CI | < 60 s on `ubuntu-latest` |
| RNF-04 | Containment | `dare-blast-radius` depends on `dare-attack-graph` only among DARE crates: no engine crate, no `dare-attack-path`, no network crate. A manifest test enforces this, and that no crate other than the CLI (and the product, if Q6 is (a)) depends on it | Enforced by tests |
| RNF-05 | Explainability | Every reached node has a witness route whose edges exist in the input graph and whose evidence ids are the graph's | 100 % |
| RNF-06 | Quality gate | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`, `cargo audit` | All green |

---

## 6. Security requirements

| ID | Requirement | Reference |
|----|-------------|-----------|
| RS-01 | The graph and the scenario are schema-validated and size- and depth-bounded before use, and treated as untrusted. The graph must also pass `validate_graph_v2` | OWASP A03 |
| RS-02 | Labels are validated and escaped as in Cycle 023, and no output carries a credential shape. Error messages name positions, never content | OWASP A02 |
| RS-03 | No file read outside the two supplied paths, no symlink followed, no URI dereferenced | OWASP A01 |
| RS-04 | No new third-party dependency; `cargo audit` clean | OWASP A06 |
| RS-05 | Secrets: none are read or needed. No environment variable changes behaviour | — |
| RS-06 | **No false containment:** `CONTAINED` requires a held control on every structural route to the node (O-03). An `INCONCLUSIVE`, `ERROR` or unassessed edge never contains | Cycle 018 aggregation |
| RS-07 | **No score:** reach is reported as counts and routes. There is no probability, likelihood or weighted number (Q3) | Cycle 023 frozen boundary |
| RS-08 | **Analysis only:** nothing is executed, sent or scheduled | Product Design §10 |
| RS-09 | **Bounded resource use** against state explosion (§4.3) | Cycle 008 threats |

---

## 7. Technical stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Rust | edition 2021, MSRV 1.88 |
| Serialization / schema | serde_json, jsonschema | workspace |
| Digests | sha2 | workspace |
| Reused crates | `dare-attack-graph` (v2 model, validators, control rule, and the continuity rule after Q1) | workspace |
| New dependencies | None | — |

---

## 8. External integrations

None. The cycle is offline analysis over local files: no network, no telemetry, and no
model provider.

---

## 9. Constraints

- **Timeline:** one cycle, Design → Blueprint → Review → Execute.
- **Infrastructure:** GitHub Actions only. The PR-open-only trigger is preserved, and a
  new CI job, `blast-radius-2026`, runs the lab.
- **Technical:**
  - an additive crate;
  - no `unwrap()` in production;
  - engines unchanged;
  - Cycle 023 outputs byte-identical;
  - Cycle 008 v1 unchanged.
- **Compliance:** lab inputs are synthetic. Users' graphs and scenarios stay local.

---

## 10. Out of scope (v1)

- **Scores and weighting:** no risk score, probability or impact weight (Q3).
- **Runtime OpenTelemetry (Cycle 025):** reach from live traces.
- **Executing or validating reach:** remains Cycles 009 (local, ROE-bound) and 022 (remote,
  authorization-bound).
- **New projection:** no new projector and no new edge kind. The three Cycle 023
  follow-ups stay out of scope, because each changes Cycle 023 or an engine rather than
  analysing the graph:
  - `EXPOSES_TOOL` and tool → resource edges;
  - an A2A remote fixture;
  - delegated-subject continuity for A2A (Q4).
- **Time and ordering:** no temporal reach ("before the credential rotates") and no dwell
  time.
- **Fleet graphs across targets:** one graph per run.
- **New property IDs and profile changes:** the registry and the eleven denominators stay
  unchanged.

---

## 11. Risks and mitigations

| # | Risk | Probability | Impact | Mitigation |
|---|------|-------------|--------|------------|
| R-01 | `CONTAINED` read as "safe" | High | High | Only a `PASS` on every route contains (RS-06). The summary says containment is by observed controls in the supplied runs only. Unreached ≠ unreachable |
| R-02 | State explosion from continuity state (actor sets) | Medium | Medium | Per-seed and total state bounds, depth bound, reported truncation (O-05, O-08) |
| R-03 | Two continuity implementations drift apart | Medium | High | One function in `dare_attack_graph::v2`, used by both crates (RF-15); the Cycle 023 lab runs unchanged in CI |
| R-04 | Seeds on graphs built without a system model name run-scoped ids that change with the run | High | Low | `node_id` seeds are allowed; `graph_id` binding refuses a scenario applied to another graph |
| R-05 | The remediation delta is read as a ranking | Medium | Medium | Counts only, no sort by "importance" beyond count with id tie-break, and the wording "if this edge's controls held" in every row |
| R-06 | Reach over-states impact where Cycle 023 lacks edges (no tool → resource edge) | Certain | Medium | The summary lists which engines contributed to the graph. The not-covered statement names the missing relation kinds |

---

## 12. Compatibility

Cycle 024 must prove that it:

1. leaves Cycle 023 `validate attack-paths` outputs byte-identical across the whole
   ATTACK-PATH-LAB after the continuity rule moves;
2. leaves `validate attack-graph --facts` and every v1 fixture output byte-identical;
3. leaves every engine crate, the registry and the eleven profile denominators
   unchanged;
4. keeps `dare-adversarial` eligibility and `dare-continuous` drift unchanged;
5. keeps the PR-open-only CI trigger, with no network access and no secrets.

**Completion rule:** every acceptance criterion maps to executed evidence in `PROOF.md`,
and defects are recorded in `REGRESSION.md`.

---

## 13. Open questions for Review

1. **Crate and shared continuity.**
   - **(a) Recommended:** a new crate, `dare-blast-radius`, depending only on
     `dare-attack-graph`. The continuity function moves from `dare-attack-path` into
     `dare_attack_graph::v2`, next to the control-state rule, and both crates call it.
   - **(b)** A module inside `dare-attack-path`. That pulls ten engine crates into blast
     radius, and graph analysis would sit with projection.
2. **Input.**
   - **(a) Recommended:** a v2 graph file only. Construction stays `validate attack-paths`,
     and the two commands chain.
   - **(b)** Also accept `--artifacts` and build the graph internally. That duplicates the
     023 entry point.
3. **Impact weighting.** The Cycle 023 Design listed "impact weighting" under 024.
   - **(a) Recommended:** no weighting. Impact is counts by target class, tenant and
     boundary, plus witness routes. This keeps the product's no-score rule.
   - **(b)** Fixed ordinal tiers derived from target class (for example destructive >
     privileged > sensitive). This is still not a number, but it is an ordering someone
     chose.
4. **A2A delegated subject** (Cycle 023 "Notes for the next cycle").
   - **(a) Recommended:** out of scope. Reach inherits Cycle 023 continuity unchanged, and
     the limitation is stated in the summary.
   - **(b)** Change C1 to remember delegators in this cycle. That changes Cycle 023 path
     verdicts and breaks O-07.
5. **Remediation delta (RF-10).**
   - **(a) Recommended:** SHOULD, bounded to 64 failed edges, counts only.
   - **(b)** MUST.
   - **(c)** Out of scope.
6. **Product integration (RF-14).**
   - **(a)** COULD: the product reads `blast_radius: <path>` and validates it.
   - **(b) Recommended:** out of scope for v1. The product already carries the v2 graph,
     and adding a second optional artifact is better done once the report layout for
     graph analyses is decided.
7. **Views.**
   - **(a) Recommended:** exactly two views, structural and uncontained.
   - **(b)** Add a third, "demonstrated" view that crosses only edges whose controls
     `FAIL`. This is narrower, and every unassessed edge would block it.

---

## 14. Approval checklist

- [ ] Functional requirements reviewed and prioritized
- [ ] "Reach over the v2 graph, no re-judging, no score" architecture accepted
- [ ] Compromise kinds and initial authority (§4.2) accepted
- [ ] The two views and the containment rule (RF-06, RS-06) accepted
- [ ] Hard maxima (§4.3) accepted
- [ ] BLAST-RADIUS-LAB classes (§4.4) accepted
- [ ] Out-of-scope boundary with Cycles 023 and 025 confirmed
- [ ] Critical risks (R-01, R-03) have accepted mitigations
- [ ] Open questions in §13 answered
