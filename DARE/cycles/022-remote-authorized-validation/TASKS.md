# Cycle 022 — Tasks

**Status:** APPROVED FOR EXECUTION  
**Approval:** APPROVED 2026-09-28 — see `APPROVAL.md`  
**Baseline:** `main @ b6f14b9`  
**Branch:** `claude/loving-newton-113zme`

Source of truth: `BLUEPRINT.md` (section references below). Each task is DONE only when its criterion is met by an executed test or command recorded in `EXECUTION/task-NNN.md`, and the Ralph Loop (`cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`, `cargo audit` when dependencies change) is green. Network capability exists only in `dare-remote-validation`, and no test or CI step contacts anything other than the loopback REMOTE-LAB.

## Checklist

- [x] task-001 — Freeze post-021 baseline, test count, pinned denominators and Action image build
- [x] task-002 — Correct the A2A evidence bridge for INCONCLUSIVE/ERROR
- [x] task-003 — Correct the MCP Auth evidence bridge for INCONCLUSIVE/ERROR
- [x] task-004 — Correct the supply-chain evidence bridge for INCONCLUSIVE/ERROR
- [x] task-005 — Validate every record in all 9 engine evidence bridges
- [x] task-006 — Add the 32-record every-bridge validation test and update the changed 018/019/020 assertions
- [x] task-007 — Create the `dare-remote-validation` crate skeleton and network-stack manifest guard
- [x] task-008 — Implement `limits.rs` hard maxima and lower-only `Limits`
- [x] task-009 — Implement `error.rs`, `ids.rs` and `canonical.rs`
- [ ] task-010 — Add the seven `schemas/remote-validation/v1` JSON schemas
- [x] task-011 — Implement `source.rs`/`schema.rs` byte, depth, hostile and schema admission
- [x] task-012 — Implement `origin.rs` `Origin::parse`
- [x] task-013 — Implement the `RemotePlan` model
- [x] task-014 — Implement the `Authorization` model and `verify` rules 1–16
- [x] task-015 — Implement `address.rs` IP classification and `permitted`
- [ ] task-016 — Implement `PinnedResolver` (`reqwest::dns::Resolve`)
- [x] task-017 — Implement `Credential` and `Scrubber`
- [ ] task-018 — Implement `RateLimiter`, the budget wrapper over `BudgetState` and `RemoteKillSwitch`
- [ ] task-019 — Implement `capture.rs` with chained digests and `verify`
- [ ] task-020 — Implement `audit.rs`
- [ ] task-021 — Implement `outcome.rs` transport overlay
- [ ] task-022 — Implement `EgressGateway::new` and `send` steps 1–10
- [ ] task-023 — Build the REMOTE-LAB harness (`LabCa` with rcgen, `LabServer`, behaviours)
- [ ] task-024 — Implement the A2A protocol client
- [ ] task-025 — Implement the MCP protocol client (JSON-RPC, single-response SSE reader, pagination, metadata GETs)
- [ ] task-026 — Implement the `dare-conversation` v1 client
- [ ] task-027 — Implement the prompt-injection live adapter and capture → transcript conversion
- [ ] task-028 — Implement the multi-turn live adapter (conversation and A2A) and capture → transcript conversion
- [ ] task-029 — Implement the A2A card and exchange projection into STATIC documents
- [ ] task-030 — Add `scenario_with_observed_resource` to `dare-mcp-auth-security` (BQ-1)
- [ ] task-031 — Implement the MCP auth metadata conversion
- [ ] task-032 — Amend the 013 and 021 adapter trait doc comments (BQ-4)
- [ ] task-033 — Implement `ledger.rs`, `evidence.rs` and `result.rs` (including self-reported marking and `summary.md`)
- [ ] task-034 — Implement `run_remote` and `replay_capture`
- [ ] task-035 — Add the REMOTE-LAB corpus (≥ 30 entries) and class-contract test
- [ ] task-036 — Add the egress, rate/budget, credential-hygiene, authorization-refusal and replay-equivalence suites
- [ ] task-037 — Add the `validate remote` and `validate replay-capture` CLI subcommands
- [ ] task-038 — Add the `remote-validation-2026` CI job
- [ ] task-039 — Add compatibility tests
- [ ] task-040 — Security, dependency and container audit
- [x] task-041 — Record the remote-validation standards provenance snapshot
- [ ] task-042 — Write the EN/PT concept page and the EN authorization reference
- [ ] task-043 — Write REGRESSION.md and PROOF.md, run the completion gate and create the cycle archive branch

## Task table

| ID | Title | Phase | Depends on | Complexity | DONE criterion |
|---|---|---|---|---|---|
| task-001 | Freeze post-021 baseline, test count, pinned denominators and Action image build | 0 — Container baseline | — | LOW | `BASELINE.md` records `b6f14b9`, the `cargo test --workspace` pass count, every pinned profile denominator, and either a successful builder-stage `docker build` or the last green `action-e2e.yml` run on `main` |
| task-002 | Correct the A2A evidence bridge for INCONCLUSIVE/ERROR | 1 — Evidence bridges | task-001 | LOW | `dare-a2a-security/src/evidence_bridge.rs` emits `observed.decision = None` and `observed.result = None` for INCONCLUSIVE and ERROR (BLUEPRINT §4.12); PASS and FAIL records are unchanged byte for byte |
| task-003 | Correct the MCP Auth evidence bridge for INCONCLUSIVE/ERROR | 1 — Evidence bridges | task-001 | LOW | same rule in `dare-mcp-auth-security/src/evidence_bridge.rs`; PASS and FAIL records unchanged |
| task-004 | Correct the supply-chain evidence bridge for INCONCLUSIVE/ERROR | 1 — Evidence bridges | task-001 | LOW | same rule in `dare-supply-chain-security/src/evidence_bridge.rs`; PASS and FAIL records unchanged |
| task-005 | Validate every record in all 9 engine evidence bridges | 1 — Evidence bridges | task-002, task-003, task-004 | MED | each bridge calls `dare_security_evidence::validate` next to `validate_secret_safety` and never returns a record that fails it; a unit test per bridge feeds a deliberately inconsistent record and gets the crate's evidence error |
| task-006 | Add the 32-record every-bridge validation test and update the changed 018/019/020 assertions | 1 — Evidence bridges | task-005 | MED | `crates/dare-agent-security-cli/tests/every_bridge_validates.rs` (the CLI already depends on all 9 engines, so Phase 1 does not wait for the new crate) builds 9 bridges × {PASS, FAIL, INCONCLUSIVE, ERROR} where the corpus offers the verdict and validates all of them; every Cycle 018/019/020 assertion that pinned `NotApplicable`/`evidence-insufficient` is updated and listed with file:line in `REGRESSION.md`; no verdict, result artifact or coverage number changes |
| task-007 | Create the `dare-remote-validation` crate skeleton and network-stack manifest guard | 2 — Skeleton | task-001 | LOW | the crate is a workspace member; `the_only_network_stack_is_reqwest` passes and fails when `rmcp`, `ureq`, `hyper` (non-dev), `openssl`, `native-tls` or a DNS/LLM crate is added; every engine crate's no-network test is untouched |
| task-008 | Implement `limits.rs` hard maxima and lower-only `Limits` | 2 — Skeleton | task-007 | LOW | constants equal BLUEPRINT §4.2; `resolve` returns the maximum for `None`, `BoundZero` for 0 and `BoundRaised` above the maximum, each tested for all five fields |
| task-009 | Implement `error.rs`, `ids.rs` and `canonical.rs` | 2 — Skeleton | task-007 | LOW | `RemoteError::is_refusal` covers exactly the six refusal variants; identifier grammars refuse bidi/control/zero-width characters without echoing them; canonical digest is key-order independent; `no_error_message_carries_input_values` passes |
| task-010 | Add the seven `schemas/remote-validation/v1` JSON schemas | 3 — Admission & authorization | task-008, task-009 | MED | authorization, plan, capture, audit, result, conversation-request and conversation-response schemas compile, self-describe, use `additionalProperties: false`, and match BLUEPRINT §4.5–§4.11 and §5.3 field for field |
| task-011 | Implement `source.rs`/`schema.rs` byte, depth, hostile and schema admission | 3 — Admission & authorization | task-010 | MED | oversize (> 256 KiB input, > 16 MiB capture), depth > 32, credential values, control/bidi characters and unknown fields are refused before deserialization into domain types; embedded schemas equal the files on disk |
| task-012 | Implement `origin.rs` `Origin::parse` | 3 — Admission & authorization | task-009 | MED | every rule of BLUEPRINT §4.3 has an accept or refuse test, including userinfo, path, query, fragment, wildcard, non-ASCII, trailing dot, `:443` normalization and shorthand IPv4 forms |
| task-013 | Implement the `RemotePlan` model | 3 — Admission & authorization | task-011 | MED | `plan.schema.json` and the Rust type agree; `PlannedRun` resolves scenarios from built-in corpora only; `a2a_policy_file` is required exactly for A2A runs |
| task-014 | Implement the `Authorization` model and `verify` rules 1–16 | 3 — Admission & authorization | task-011, task-012, task-013 | HIGH | each rule of BLUEPRINT §4.5 has a refusal test that asserts its `AuthorizationRefusal` variant, the order of checks, and that no DNS lookup or socket happened; window edges `now == not_before` (allowed) and `now == not_after` (refused) tested; `VerifiedAuthorization` is not constructible outside `verify` |
| task-015 | Implement `address.rs` IP classification and `permitted` | 4 — Address policy | task-009 | MED | every row of BLUEPRINT §4.4 and its boundaries (e.g. `172.15.255.255` Public, `172.16.0.0` Private, `172.31.255.255` Private, `172.32.0.0` Public, IPv4-mapped IPv6) is tested; `Metadata`, `LinkLocal` and `Reserved` are never permitted |
| task-016 | Implement `PinnedResolver` (`reqwest::dns::Resolve`) | 4 — Address policy | task-015 | HIGH | first lookup classifies all addresses and refuses the host if any is disallowed; later lookups return the pinned set; rebinding (public then loopback) and mixed answers are refused through the `cfg(test)` lookup injection; no real DNS in tests |
| task-017 | Implement `Credential` and `Scrubber` | 5 — Gateway | task-009 | MED | value held in `Zeroizing`; `Debug` redacts; header marked sensitive; scrubber replaces the raw, base64 (standard and URL-safe) and percent-encoded forms and the Cycle 021 credential shapes; replacement counts returned |
| task-018 | Implement `RateLimiter`, the budget wrapper over `BudgetState` and `RemoteKillSwitch` | 5 — Gateway | task-008 | MED | spacing is exactly `1000 ms / max_rps` under `tokio::time::pause`; the budget is derived from `EffectiveLimits` as BLUEPRINT §4.8 step 4 states; every kill trigger in §4.8 flips the switch and blocks the next send |
| task-019 | Implement `capture.rs` with chained digests and `verify` | 6 — Capture, audit, overlay | task-009 | MED | chain seed and link construction match BLUEPRINT §4.9; a one-byte change, gap, duplicate or reordered index gives `CaptureTampered` with the entry index; timing fields never enter a verdict conversion |
| task-020 | Implement `audit.rs` | 6 — Capture, audit, overlay | task-019 | MED | audit events chain like the capture; `totals.requests == capture.entries.len()` is checked; a refusal before admission writes nothing |
| task-021 | Implement `outcome.rs` transport overlay | 6 — Capture, audit, overlay | task-009 | LOW | every row of BLUEPRINT §4.10 is tested; `no_transport_outcome_can_produce_pass` enumerates every `TransportOutcome` against all four verdicts |
| task-022 | Implement `EgressGateway::new` and `send` steps 1–10 | 5 — Gateway | task-014, task-016, task-017, task-018, task-019, task-020 | HIGH | each step of BLUEPRINT §4.8 has a test; client has no proxy (tested with `HTTPS_PROXY` pointed at an unreachable address), no redirects, https only, pool 0; only the fixed headers are sent; oversize responses are dropped, never captured |
| task-023 | Build the REMOTE-LAB harness (`LabCa` with rcgen, `LabServer`, behaviours) | 7 — Lab | task-007 | HIGH | `rcgen` added as a dev-dependency only; the CA and server keys stay in memory (a scan of the temp dir and repository tree finds no key); servers bind to `127.0.0.1` on ephemeral ports and log every hit with its time, path and peer |
| task-024 | Implement the A2A protocol client | 8 — Protocols | task-022, task-023 | MED | `A2A_AGENT_CARD_GET`, `A2A_MESSAGE_SEND` and `A2A_TASKS_GET` round-trip against the lab with the exact bodies of BLUEPRINT §5.4; a method outside the plan is refused before send |
| task-025 | Implement the MCP protocol client (JSON-RPC, single-response SSE reader, pagination, metadata GETs) | 8 — Protocols | task-022, task-023 | HIGH | every MCP method of BLUEPRINT §5.4 round-trips; `resources/read` and `prompts/get` accept only values listed in the same run; at most 5 pages; SSE reading stops at the first matching `id` or the byte bound; an authorization server outside `origins` is recorded but never fetched |
| task-026 | Implement the `dare-conversation` v1 client | 8 — Protocols | task-022, task-023 | MED | request and response validate against their schemas; the request carries no node id, invariant, canary or expected outcome; mismatched echo fields and non-schema bodies give `ProtocolViolation` |
| task-027 | Implement the prompt-injection live adapter and capture → transcript conversion | 9 — Engine conversions | task-021, task-026 | HIGH | `LiveTrialAdapter` implements 013's `HarnessAdapter`; the conversion produces a transcript that 013's `ReplayAdapter` binds; a lab vulnerable target gives FAIL and its secure twin gives the same verdict as the offline scenario |
| task-028 | Implement the multi-turn live adapter (conversation and A2A) and capture → transcript conversion | 9 — Engine conversions | task-021, task-024, task-026 | HIGH | `LiveConversationAdapter` implements `ConversationAdapter` through `block_in_place`; the transcript binds with 021's `ReplayAdapter`; lab eroding and secure agents give the same verdicts as MULTITURN-LAB offline; A2A replies project into `output_text` |
| task-029 | Implement the A2A card and exchange projection into STATIC documents | 9 — Engine conversions | task-021, task-024 | HIGH | every row of BLUEPRINT §6.1 and every rule of §6.2 has a test; `.remote-work/` documents are read by the engine's `StaticAdapter` with `evidence_is_synthetic() = false`; invariants needing non-observable fields are never PASS |
| task-030 | Add `scenario_with_observed_resource` to `dare-mcp-auth-security` (BQ-1) | 9 — Engine conversions | task-001 | MED | the function is additive and network-free (the crate's no-network test still passes); URL → `SyntheticUri` mapping is deterministic and equality preserving; trust class is `SELF_REPORTED`; the existing 018 lab results are unchanged |
| task-031 | Implement the MCP auth metadata conversion | 9 — Engine conversions | task-021, task-025, task-030 | MED | live metadata from the lab produces a derived scenario that the 018 engine decides; mismatched resource and unlisted authorization server give FAIL; the secure twin matches its offline verdict |
| task-032 | Amend the 013 and 021 adapter trait doc comments (BQ-4) | 9 — Engine conversions | task-027, task-028 | LOW | the doc comments name `dare-remote-validation`'s live adapters as the single exception and state their results are never used as verdicts; no engine code changes (diff limited to comments) |
| task-033 | Implement `ledger.rs`, `evidence.rs` and `result.rs` (including self-reported marking and `summary.md`) | 10 — Runner & REMOTE-LAB | task-027, task-028, task-029, task-031 | HIGH | every artifact is admitted before write, including the result itself; evidence is re-tagged `ProtocolResponse` with `extensions["dare.remote"]` and re-validated; every live PASS that relies on a target-reported field carries the BQ-2 marking; the summary lists unobserved and non-observable items |
| task-034 | Implement `run_remote` and `replay_capture` | 10 — Runner & REMOTE-LAB | task-020, task-033 | HIGH | the live pass result is discarded and the verdict comes from the replay; `replay_capture` opens no socket (lab hit count unchanged); both entry points produce byte-identical results for the same capture |
| task-035 | Add the REMOTE-LAB corpus (≥ 30 entries) and class-contract test | 10 — Runner & REMOTE-LAB | task-034 | HIGH | `tests/remote_lab.rs` asserts every class of BLUEPRINT §7.2; vulnerable targets FAIL on their invariant, secure twins match the offline verdict, egress hostility is refused or killed with 0 off-origin hits, transport faults never PASS |
| task-036 | Add the egress, rate/budget, credential-hygiene, authorization-refusal and replay-equivalence suites | 10 — Runner & REMOTE-LAB | task-035 | MED | each file of BLUEPRINT §7.3 passes; planted credential canary appears 0 times in artifacts, stdout, stderr and error displays; consecutive lab hits ≥ 500 ms apart at `max_rps = 2`; every refusal leaves the lab log empty |
| task-037 | Add the `validate remote` and `validate replay-capture` CLI subcommands | 11 — CLI & CI | task-034 | MED | flags match BLUEPRINT §5.1; the forbidden-flag test covers all 17 flags; exit codes 0/1/2/3 are each tested; nothing is written on refusal; `ctrl_c` triggers `OperatorStop` |
| task-038 | Add the `remote-validation-2026` CI job | 11 — CI | task-036, task-037 | LOW | the job runs only loopback-lab tests, keeps the PR-open trigger, and references no `secrets.*` (asserted by a test that reads `ci.yml`); it runs locally with `scripts/run-ci-job-locally.py` |
| task-039 | Add compatibility tests | 12 — Audit | task-037 | MED | `dare-adversarial` still refuses `local_only = false`; `dare-continuous` does not depend on this crate; engine no-network tests unchanged; registry and profile digests unchanged; CI trigger unchanged; every `include_str!` lies under a Docker-copied directory |
| task-040 | Security, dependency and container audit | 12 — Audit | task-038, task-039 | MED | `cargo audit` clean (including rcgen); `scripts/k22/assert_no_real_credentials.py` clean with its lab-host allowlist; builder-stage image builds; the in-image binary exits 3 on `validate remote` with an expired authorization and networking disabled |
| task-041 | Record the remote-validation standards provenance snapshot | 13 — Docs & proof | task-001 | LOW | `standards/remote-validation/2026/provenance.json` pins the A2A, MCP, RFC 9728 and RFC 8414 versions the protocol clients target; JSON validates |
| task-042 | Write the EN/PT concept page and the EN authorization reference | 13 — Docs & proof | task-037 | LOW | three pages added and linked in both `SUMMARY.md`; they state what a remote result does not claim; EN and PT mdBook builds are green |
| task-043 | Write REGRESSION.md and PROOF.md, run the completion gate and create the cycle archive branch | 13 — Docs & proof | task-040, task-041, task-042 | MED | every Design acceptance item maps to an executed test in `PROOF.md`; `scripts/k22/verify_proof_citations.py` passes; full completion gate green; `agent/cycle-022-remote-authorized-validation` is pushed at the final cycle commit |

## Note on the Blueprint

- **task-006** places the 32-record bridge test in `crates/dare-agent-security-cli/tests/` rather than in the new crate (BLUEPRINT §3). The CLI already depends on all nine engines, so the bridge correction (Phase 1) can finish before the new crate exists. The test and its assertions are unchanged.
