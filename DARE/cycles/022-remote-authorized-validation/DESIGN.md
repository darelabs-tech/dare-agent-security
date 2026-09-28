# Cycle 022 — Design: Remote Authorized Validation

**Version:** v0.1 | **Date:** 2026-09-28 | **Status:** DRAFT — Q1–Q4 decided 2026-09-28; Q5 and final Design approval pending  
**Base branch:** `main` (`b6f14b9`, Cycles 001–021 merged; see `../ACCEPTANCE.md`)  
**Proposed crate:** `crates/dare-remote-validation`  
**Also in scope:** correction of the Cycle 001 evidence bridges in `dare-a2a-security`,
`dare-mcp-auth-security` and `dare-supply-chain-security` (§4.8). The Product Owner
moved this into Cycle 022 on 2026-09-27.

---

## 1. Description

Cycles 009–021 validate agents only offline, through replayed captures, simulated
reference agents or local-synthetic targets. `AUTHORIZED_DYNAMIC` exists as a mode
name, but Cycle 009 refuses every ROE with `local_only = false`. Every network method
is blocked, and only `dare-mcp-discovery` performs network I/O (a read-only MCP
listing, with no authentication). An AppSec team therefore cannot yet ask the question
this product exists to answer against the system it actually runs: *does this agent,
deployed on our staging environment, hold the property?*

Cycle 022 adds **remote validation under an explicit, digest-bound, time-boxed
authorization**, against a small closed set of wire protocols:
- A2A;
- MCP;
- one closed, DARE-defined conversational HTTP contract (Q2).

The central design choice is **live capture, offline verdict**:

1. A new crate, `dare-remote-validation`, is the only component that talks to a remote
   target. It sends only the pre-approved turns of an existing engine's scenario, through
   an egress gateway that enforces the authorization. It records every exchange into a
   digest-chained **capture**.
2. The capture is converted into the owning engine's **existing REPLAY input** (Cycles
   013, 018, 020, 021). The engine decides the verdict exactly as it does today, with no
   new code path and still without a network dependency.

The engine answers one question:

> Under authorization *A*, did target *T* at origin *O* preserve property *P* on the
> exchanges actually observed between *t₀* and *t₁*, as decided by the owning engine
> from a capture that anyone can replay offline to the same verdict?

It does **not** say a target is secure. It does not cover unobserved behaviour, and it
does not scan, discover or crawl anything.

---

## 2. Objectives and success metrics

| # | Objective | Verifiable metric | Target |
|---|-----------|-------------------|--------|
| O-01 | No egress outside the authorization | Connections to an origin or resolved IP not in the authorization, measured by REMOTE-LAB hostile servers (redirect to another host, DNS answer that changes, private-IP answer) | 0 |
| O-02 | Fail-closed authorization | Invalid, expired, not-yet-valid, digest-mismatched, unconfirmed or scope-exceeding authorizations that are refused **before the first byte is sent** | 100 % (0 bytes of egress) |
| O-03 | Replay equivalence | REMOTE-LAB live runs whose capture replays offline to a byte-identical engine result | 100 % |
| O-04 | No false PASS | Runs with a timeout, a connection or TLS error, `429`/`5xx`, an unexpected auth challenge, or an exhausted budget that end in PASS | 0 |
| O-05 | Secret hygiene | Occurrences of the planted credential canary in any artifact, capture, log line, error message or panic output | 0 |
| O-06 | Budget and rate enforcement | Requests beyond `max_requests`; observed rate above `max_rps`, measured by the lab server | 0 / 0 |
| O-07 | Detection parity | Vulnerable REMOTE-LAB targets reported FAIL / secure twins reported PASS, each matching the verdict the same scenario gives offline | 100 % / 100 % |
| O-08 | Compatibility | Engines' no-network manifest tests and offline results unchanged; existing property IDs and profile denominators unchanged | 0 regressions |
| O-09 | Evidence-bridge correctness | Evidence bridges × verdicts (8 × 4) whose records pass `dare_security_evidence::validate` | 32 / 32 |

---

## 3. Stakeholders

| Role | Name / team | Main interest |
|------|-------------|---------------|
| Product Owner | DARE Labs | Scope, approval, and the boundary with Cycles 023–025 |
| Tech Lead | DARE Agent Security maintainers | Keeping all network capability in one crate; engines stay offline |
| AppSec / red team | Primary users | Evidence against their real staging agents, reproducible offline |
| Target owner | Customer platform team | An authorization they signed off on is honoured exactly: origins, time window, rate, data classes |
| Security reviewers | DARE Review | Proof that the tool cannot be pointed at an unauthorized system or leak a credential |
| Legal / compliance | Customer | A record of what was sent, when, to whom and under which authorization |

---

## 4. Functional requirements

| ID | Requirement | Priority | Acceptance criterion |
|----|-------------|----------|----------------------|
| RF-01 | Remote authorization document | MUST | A new schema, `schemas/remote-validation/v1/authorization.schema.json`, covering the fields in §4.1. It is admitted like every other input (size, depth, hostile sweep, `additionalProperties: false`), and its digest is pinned by the run plan |
| RF-02 | Fail-closed authorization check | MUST | Before any DNS lookup or socket, the run checks all of the following, and a failure is a refusal (exit 3, 0 bytes sent): the time window; the plan-to-authorization digest; origin ⊆ authorization; protocol and method ⊆ authorization; scenario id and digest ⊆ authorization; environment; operator confirmation (RF-03) |
| RF-03 | Operator confirmation | MUST | The CLI requires `--confirm-origin <origin>`, which must equal the authorized origin byte for byte. There is no `--yes` and no confirmation from an environment variable |
| RF-04 | Egress gateway | MUST | The single place that opens sockets. It is HTTPS-only (loopback lab excepted, §4.5), verifies TLS, follows no redirects, and resolves DNS once, pinning and re-checking the IP on every connection. Private, loopback, link-local and metadata ranges are refused unless the authorization's `network_scope` names them. It bounds request and response bytes and applies connect, read and total timeouts |
| RF-05 | Budget, rate limit and kill switch | MUST | These reuse the Cycle 009 `ExecutionBudget`/`BudgetState` and `kill_switch` semantics, plus `max_requests`, `max_rps` and `max_duration`. The first violation stops the run, and the next request is never sent |
| RF-06 | Closed wire protocols | MUST | The adapters are **A2A** (Agent Card `GET` plus `message/send` over JSON-RPC) and **MCP** (streamable HTTP: `initialize`, `*/list`, `resources/read`, `prompts/get`, plus the Cycle 018 auth-metadata `GET`s). The `dare-conversation` contract has a single `POST`. Method lists are closed enums, and no free-form request is possible |
| RF-07 | Pre-approved payloads only | MUST | Every request body is produced from an existing engine scenario that is named by id and digest in the authorization: MULTITURN-LAB graph nodes (021), prompt-injection vectors (013), A2A scenarios (020) or MCP-auth scenarios (018). Nothing is generated, templated or mutated at run time |
| RF-08 | Capture | MUST | Every exchange is recorded as a digest-chained capture: request digest and redacted bounded body, response status, redacted bounded body and digest, and timing. It is bound to the authorization digest and origin. Tampering is refused at replay (same contract as Cycle 021 RF-10) |
| RF-09 | Offline verdict by the owning engine | MUST | A capture converts to the owning engine's existing REPLAY input, and that engine decides. `dare-remote-validation` has no verdict logic of its own beyond transport outcome → ERROR/INCONCLUSIVE |
| RF-10 | Credential by reference | MUST | The authorization names an environment variable (`credential_ref`), never a value. The value is read once, sent only to the authorized origin as a bearer or API-key header, and never logged. Before any write, the capture and every artifact are scrubbed for the value **and** for credential shapes |
| RF-11 | Transport outcomes never PASS | MUST | Timeout, connection or TLS error, `401/403` where the scenario expected none, `429`, `5xx`, oversize, protocol violation or budget stop → ERROR (harness or transport) or INCONCLUSIVE (evidence missing), per a closed table in the Blueprint |
| RF-12 | CLI | MUST | `dare-agent-security validate remote` with `--authorization`, `--plan`, `--confirm-origin`, `--output-dir` and optional lower-only bounds; `validate replay-capture` for offline re-evaluation. Forbidden flags: a raw URL, header, token, key, proxy, `--insecure`/skip-TLS, generator, seed or shell |
| RF-13 | Artifacts | MUST | `remote-result.json`, `remote-capture.json`, `remote-evidence.json` (Cycle 001, `ObservationSource::ProtocolResponse`), `remote-audit.json` (see RF-14) and `summary.md`, each admitted through the output ledger before write |
| RF-14 | Audit record | MUST | An append-only, digest-chained audit record covering the authorization digest, operator confirmation, every request's origin, method, time and outcome, the stop reason and totals (requests, bytes, duration). It is written even for refusals that happen after admission |
| RF-15 | REMOTE-LAB | MUST | At least 30 entries run against in-process loopback HTTPS lab servers: vulnerable and secure A2A and MCP targets, plus hostile servers (redirect off-origin, DNS answer that changes, oversized or slow responses, `429`/`5xx` storms, a server that echoes credentials back, TLS mismatch). Every class has a control |
| RF-16 | Coverage | SHOULD | Remote evidence feeds the Cycle 006 coverage report as `SupportedMode::Dynamic` for the **existing** properties. No new property IDs are added and no profile denominator changes |
| RF-17 | Conversational HTTP adapter | MUST | Decided in Q2. A single closed request/response contract for a conversational agent endpoint, used by 013 and 021 scenarios |
| RF-18 | Cycle 009 compatibility | MUST | `dare-adversarial` keeps refusing `local_only = false` ROEs. Remote validation is a separate, explicit entry point and never widens the Cycle 009 runner |
| RF-19 | Continuous (Cycle 010) boundary | MUST | `dare-continuous` cannot schedule a remote run. Each remote run needs a live authorization and a human confirmation |
| RF-20 | Evidence-bridge correction | MUST | See §4.8 |

### 4.1 Authorization document (fields)

| Field | Meaning |
|---|---|
| `schema_version` | `"1"` |
| `authorization_id` | A validated identifier |
| `target_owner`, `approved_by` | Free text, recorded in the audit (signature: see Q1) |
| `environment` | `lab` \| `test` \| `staging`. `production` is refused in v1 (Q3) |
| `origins[]` | Exact `https://host[:port]` origins. No wildcards, paths, credentials, query or fragment |
| `network_scope` | `public` (default) \| `private` \| `loopback_lab`. The last two must be named explicitly |
| `not_before`, `not_after` | RFC 3339 window, at most 7 days long |
| `protocols` | A subset of `a2a`, `mcp`, `dare-conversation` |
| `methods` | A subset of the closed method enum for each protocol |
| `scenarios[]` | Engine, scenario id and scenario digest, which pins every payload that may be sent |
| `data_classes` | A subset of `SYNTHETIC`, `CANARY`, `TEST` (from Cycle 009) |
| `credential_ref` | Optional. The **name** of an environment variable. It must match `^DARE_REMOTE_[A-Z0-9_]{1,48}$` |
| `limits` | `max_requests`, `max_rps`, `max_duration_s`, `max_request_bytes`, `max_response_bytes`. Input may only lower them |
| `prohibited` | Always includes state mutation, credential extraction, destructive operations and external publication |

### 4.2 Hard maxima (input may only lower them)

| Maximum | Value |
|---|---|
| Requests per run | 500 |
| Rate | 2 requests per second |
| Duration | 30 minutes |
| Response body | 1 MiB |
| Request body | 64 KiB |
| Authorization window | 7 days |
| Origins per authorization | 4 |

### 4.3 Wire protocols in v1

| Protocol | Allowed operations | Engines served |
|---|---|---|
| A2A | `GET /.well-known/agent-card.json`, JSON-RPC `message/send`, `tasks/get` | 020 (card and exchange invariants), 021 (multi-turn over A2A) |
| MCP (streamable HTTP) | `initialize`, `tools/list`, `resources/list`, `resources/read`, `prompts/list`, `prompts/get`, plus the RFC 9728 / RFC 8414 metadata `GET`s | 018 (auth metadata), 002 (inventory, now with authentication) |
| DARE conversational contract (`dare-conversation`) | One `POST` carrying the closed JSON contract `{conversation_id, turn}` → `{output, actions[]}` | 013, 021 |

`tools/call` is **not** in v1: it executes code on the target (Q4).

### 4.4 Verdict mapping

- **Target verdict:** the owning engine's verdict over the replayed capture, unchanged.
- **Transport outcomes:** each maps to ERROR or INCONCLUSIVE through a closed table, never to PASS.
- **Aggregation:** unchanged. FAIL > ERROR > INCONCLUSIVE > PASS (Cycle 018), and a concrete FAIL survives.
- **Every live PASS carries a bounded claim:** origin, authorization id, the time window actually observed, and the scenarios run. Each summary states that unobserved behaviour is not claimed.

### 4.5 REMOTE-LAB (at least 30 entries)

The lab uses in-process HTTPS servers on loopback with a test CA generated at test time
(no private key is checked in), under `environment: lab` and `network_scope: loopback_lab`.

| Range | Theme |
|---|---|
| 001–008 | A2A: vulnerable and secure agents for the Cycle 020 invariants, and multi-turn erosion over A2A |
| 009–016 | MCP: auth-metadata defects and secure twins (Cycle 018), and authenticated inventory |
| 017–022 | Egress hostility: off-origin redirect, DNS answer that changes, private-IP answer, a TLS name mismatch → refused or ERROR, 0 off-origin bytes |
| 023–027 | Transport faults: timeout, slow drip, oversize, `429` storm, `5xx` → never PASS |
| 028–030 | Credential hygiene: a server that echoes the token, a token in an error body, a token in a header → scrubbed, 0 leaks |
| + | Refusals: an expired, future, tampered, unconfirmed or scope-exceeding authorization → exit 3, 0 bytes |

### 4.6 Hostile / refusal corpus

- **Authorization documents:**
  - origins with wildcards, userinfo, IP literals in private ranges, or IDN or bidi tricks;
  - windows longer than 7 days, or with `not_after` before `not_before`;
  - `credential_ref` that does not match the pattern, or a credential *value* placed in any field.
- **Plans:**
  - a plan whose scenario digest is not in the authorization;
  - a method outside the closed enum;
  - a bound above a hard maximum.

### 4.7 CLI

**Allowed:**
- local authorization, plan and capture paths;
- `--confirm-origin`;
- the output directory;
- lower-only bounds.

**Forbidden:**
- a raw URL or endpoint;
- a header, token or key;
- a proxy;
- an option that disables TLS verification;
- following redirects;
- a seed, generator or shell.

### 4.8 Evidence-bridge correction (moved into this cycle)

**Defect.** In `dare-a2a-security`, `dare-mcp-auth-security` and
`dare-supply-chain-security`, each `evidence_bridge.rs` writes
`observed.decision = NotApplicable` for INCONCLUSIVE and ERROR, against
`expected.decision = Deny`. The Cycle 001 `ExactOutcomeComparator` reads that as a
**Mismatch**, and `validate_verdict_consistency` rejects the record ("INCONCLUSIVE/ERROR
cannot masquerade as FAIL"). None of the three bridges calls
`dare_security_evidence::validate`, so they emit invalid records silently. The other five
bridges (013–017) already emit `decision: None`, `result: None` for these verdicts.

**Correction:**
1. For INCONCLUSIVE and ERROR, the three bridges emit `observed.decision = None`.
   `observed.result` keeps its descriptive string or becomes `None`; the Blueprint picks
   one, and it must be the same across all 8 bridges.
2. Every bridge validates each record with `dare_security_evidence::validate` before
   returning it, and fails closed on a violation.
3. A workspace-level test builds a record for each of the 8 bridges × 4 verdicts and
   validates it (O-09).

**Compatibility.** This changes the bytes of the `*-evidence.json` artifacts of Cycles
018, 019 and 020 for INCONCLUSIVE and ERROR records only. No verdict, property,
profile or result artifact changes. `REGRESSION.md` records the change.

---

## 5. Non-functional requirements

| ID | Category | Requirement | Target |
|----|----------|-------------|--------|
| RNF-01 | Determinism | Live runs are not deterministic, but verdicts are: the same capture always gives a byte-identical result | 10/10 replays identical |
| RNF-02 | Boundedness | The hard maxima of §4.2; every limit is enforced before the request that would exceed it | 0 overshoot |
| RNF-03 | Performance | The full REMOTE-LAB in CI, on loopback | < 120 s on `ubuntu-latest` |
| RNF-04 | Containment | Network capability lives in `dare-remote-validation` (and the existing `dare-mcp-discovery`) only. Every engine crate keeps its no-network manifest test unchanged | Enforced by tests |
| RNF-05 | Observability | Every stop reason is explicit (`COMPLETED`, `FIRST_FAIL`, `BUDGET_EXHAUSTED`, `RATE_LIMITED`, `TRANSPORT_ERROR`, `KILL_SWITCH`, `WINDOW_EXPIRED`), and the audit record is always written after admission | 100 % of runs |
| RNF-06 | Availability of the target | Never more than `max_rps`. On `429`/`5xx`, stop; never retry-storm | 0 retries beyond the budget |
| RNF-07 | Quality gate | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`, `cargo audit` | All green |

---

## 6. Security requirements

| ID | Requirement | Reference |
|----|-------------|-----------|
| RS-01 | Every input (authorization, plan, capture, scenario) is schema-validated and size-bounded before use. Every response body is untrusted, bounded and parsed with depth limits | OWASP A03 |
| RS-02 | The credential value never reaches an artifact, log, error or panic. It is scrubbed by value and by shape before every write, and it is held in memory that is zeroed on drop | OWASP A02 |
| RS-03 | Access control **per target**: a request leaves only for an origin, IP class, protocol, method and scenario that the authorization grants, checked on **every** request, not once per run | OWASP A01 |
| RS-04 | No new dependency with a HIGH/CRITICAL advisory. Reuse reqwest/rustls from the workspace. Any new crate (Q1, lab CA) is justified in the Blueprint | OWASP A06 |
| RS-05 | Secrets come only from environment variables named by the authorization. The CLI accepts no secret, and fixtures contain none (the credential sweep extends to Cycle 022) | Secrets policy |
| RS-06 | **SSRF / egress pinning**: DNS is resolved once and pinned; private, link-local and metadata IPs are refused by default; redirects are never followed; the IP is re-checked on every connect | OWASP A10 |
| RS-07 | **No generated payloads**: every byte sent comes from a digest-pinned scenario named in the authorization | Cycle 021 RS-06 |
| RS-08 | **No state mutation**: v1 has no method that executes or writes on the target (`tools/call` is excluded, Q4) | Product Design §10.4 |
| RS-09 | **No false PASS** from any transport outcome | Cycles 018–021 |
| RS-10 | **Target protection**: rate limit, budget and kill switch are enforced client-side, and a stop is immediate | Cycle 009 |
| RS-11 | **Audit integrity**: the audit record is digest-chained and bound to the authorization digest; a missing or altered entry is detected on replay | Compliance |
| RS-12 | **No telemetry**: no cloud upload and no third-party AI API are ever called by the tool itself. The only remote peer is the authorized target | Product privacy mode |

---

## 7. Technical stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Rust | edition 2021, MSRV 1.88 |
| HTTP / TLS | reqwest (rustls) | 0.13 (workspace, already used by `dare-mcp-discovery`) |
| MCP client | rmcp | 3.1 (workspace), if streamable-HTTP auth headers are supported; otherwise a thin JSON-RPC client over reqwest (Blueprint) |
| Async runtime | tokio | workspace (adds the `net`/`time` features to this crate only) |
| Serialization / schema | serde_json, jsonschema | workspace |
| Digests | sha2 | workspace |
| Reused crates | `dare-security-evidence`, `dare-adversarial` (budget and kill switch), `dare-coverage`, and engine REPLAY inputs from `dare-prompt-injection`, `dare-mcp-auth-security`, `dare-a2a-security`, `dare-multi-turn-security` | workspace |
| Lab | In-process HTTPS servers on loopback (axum/hyper or rustls directly, per Blueprint) with a CA generated at test time | Dev-dependencies only |

---

## 8. External integrations

| System | Type | Protocol | Direction | Data exchanged | Owner |
|---|---|---|---|---|---|
| Authorized A2A agent | Target under test | HTTPS, JSON-RPC 2.0 | Outbound | Pre-approved synthetic/canary messages; Agent Card | Target owner |
| Authorized MCP server | Target under test | HTTPS, streamable HTTP | Outbound | Read-only listings, reads, auth metadata | Target owner |
| Conversational agent endpoint | Target under test | HTTPS, JSON (`dare-conversation` contract) | Outbound | Pre-approved synthetic/canary turns; bounded outputs and declared actions | Target owner |

There is no other integration: no telemetry, no cloud service and no model provider
called by the tool.

---

## 9. Constraints

- **Timeline:** one cycle, Design → Blueprint → Review → Execute. The Blueprint does not start before this Design is approved.
- **Infrastructure:** GitHub Actions only. **CI never contacts a remote target**: it has no secrets and runs the REMOTE-LAB on loopback. The PR-open-only trigger is preserved.
- **Technical:**
  - an additive crate;
  - no `unwrap()` in production;
  - engines stay offline;
  - Cycle 009's refusal of remote ROEs is preserved.
- **Compliance:**
  - lab fixtures are synthetic only;
  - users' captures stay local;
  - nothing is published without explicit authorization (Product Validation Program, Phase 3).
- **Legal:** the tool enforces the authorization, but responsibility for its truth stays with the operator and target owner. The docs say so explicitly.

---

## 10. Out of scope (v1)

- **Production targets:** refused in v1 (Q3).
- **State-changing operations:** `tools/call`, writes, and A2A tasks that trigger side effects beyond a message exchange (Q4).
- **Discovery, scanning or crawling:** exact origins only, with no port or path enumeration and no following of links found in responses.
- **Generated attacks:** no attacker-LLM, mutation, fuzzing or load testing; no WAF or rate-limit evasion.
- **Calling model providers directly** (OpenAI/Anthropic-style APIs) as targets (Q2).
- **Scheduled or continuous remote runs:** Cycle 010 stays offline.
- **Attack-path construction (023), blast radius (024), runtime OpenTelemetry (025).**
- **New property IDs.** Remote validation is a mode that produces evidence for the existing properties.

---

## 11. Risks and mitigations

| # | Risk | Probability | Impact | Mitigation |
|---|------|-------------|--------|------------|
| R-01 | The tool is pointed at a system nobody authorized | Medium | High | Exact-origin authorization, `--confirm-origin`, time window, audit record, no raw URL flag; signature is Q1 |
| R-02 | SSRF / DNS rebinding reaches an internal service | Medium | High | Pinned DNS; private and metadata IPs refused by default; no redirects; the IP is re-checked per connect; hostile lab entries 017–022 |
| R-03 | Credential leak through captures, errors or echoes | Medium | High | Reference-only credential, scrub by value and shape, planted canary test (O-05), zeroize |
| R-04 | Harm to the target (load, side effects) | Low | High | 2 rps maximum, 500 requests, no mutating methods, stop on `429`/`5xx`, staging only |
| R-05 | Non-deterministic live responses read as flaky verdicts | High | Medium | Verdicts come only from replayed captures (RNF-01); the bounded PASS claim names the observed window |
| R-06 | Network code leaks into the engines | Low | High | Engines consume only captures; existing no-network tests unchanged (RNF-04) |
| R-07 | The bridge correction changes artifacts other tools consume | Low | Medium | Only INCONCLUSIVE and ERROR evidence records change, and they become *valid*; recorded in REGRESSION.md and the changelog |
| R-08 | The lab needs a TLS key that trips the credential sweep | Medium | Low | Generate the CA at test time; check in no key |
| R-09 | Protocol drift in A2A/MCP specifications | Medium | Medium | Closed method enums pinned to the versions recorded in a standards provenance snapshot (as in Cycles 020–021) |

---

## 12. Compatibility

Cycle 022 must prove that it:

1. preserves all property IDs and profile denominators;
2. leaves `dare-adversarial` refusing `local_only = false` and blocking network methods in its own runner;
3. leaves every engine's offline modes byte-identical and its no-network manifest test unchanged;
4. changes the Cycle 018/019/020 evidence bridges only as described in §4.8;
5. preserves Cycle 018 aggregation and the Cycle 001 evidence and redaction contracts;
6. keeps the PR-open-only CI trigger, with no network target and no secrets in CI.

**Completion rule:** every acceptance criterion maps to executed evidence in `PROOF.md`,
and defects are recorded in `REGRESSION.md`.

---

## 13. Open questions for Review

1. **Authorization signature — DECIDED (2026-09-28):** (a) digest pin plus `--confirm-origin` plus the audit record, with no new dependency. The schema reserves an optional `signature` field so that a detached Ed25519 signature can be added later as a compatible change.
2. **Conversational HTTP contract — DECIDED (2026-09-28):** (b) one closed, DARE-defined JSON contract (`{conversation_id, turn}` → `{output, actions[]}`). RF-17 is therefore MUST. No OpenAI-compatible or provider shape is supported.
3. **Production — DECIDED (2026-09-28):** `environment: production` is refused in v1. Only `lab`, `test` and `staging` are accepted.
4. **`tools/call` and side-effecting methods — DECIDED (2026-09-28):** excluded from v1. Only read and message-exchange operations are allowed.
5. **Evidence-bridge `observed.result`** for INCONCLUSIVE and ERROR. Choose one:
   - (a) `None`, the same as the 013–017 bridges;
   - (b) keep the descriptive string.

   **Recommendation:** (a), so that all eight bridges are uniform.

---

## 14. Approval checklist

- [ ] Functional requirements reviewed and prioritized
- [ ] "Live capture, offline verdict" architecture accepted (engines stay offline)
- [ ] Authorization fields (§4.1) and hard maxima (§4.2) accepted
- [ ] Closed wire protocols and methods (§4.3) accepted
- [ ] Security requirements RS-03, RS-06 to RS-11 validated by the Tech Lead
- [ ] Evidence-bridge correction (§4.8) and its artifact change accepted
- [ ] Out-of-scope boundary with Cycles 023–025 confirmed
- [ ] Critical risks (R-01, R-02, R-03) have accepted mitigations
- [ ] Open questions in §13 answered (Q1–Q4 decided 2026-09-28; Q5 open)
