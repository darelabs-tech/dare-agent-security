# Cycle 023 — Baseline

**Status:** DONE  
**Measured on:** 2026-09-28  
**Baseline commit:** `main @ 32909ea` (merge of PR #47). Its tree `9d440e66…` is identical to
the Cycle 022 hotfix commit `c2f56b3`, verified with
`git rev-parse 32909ea^{tree} c2f56b3^{tree}`.

Every later claim about what Cycle 023 added or changed is a difference against these
measured numbers.

## Workspace

| Measure | Value | How measured |
|---|---|---|
| `cargo test --workspace --no-fail-fast` result suites | 314 | count of `test result:` lines, run on `c2f56b3` (same tree) |
| Tests passed / failed / ignored | 4 224 / 0 / 4 | sum over those lines |
| Workspace members | 22 | `Cargo.toml` `[workspace].members` |
| Registry v1 / v2 properties | 20 / 65 | `schemas/coverage/v{1,2}/registry.json` |
| Registry v1 digest (SHA-256 of file bytes) | `155ba470453ab59654a48b5cf29b40278137d126427bde394188b4af4b7fed71` | `sha256sum` |
| Registry v2 digest | `e8c5004c920c53606949ad537fb24d1e2f5d50ba23b26a75081afedf0f9737e9` | `sha256sum` |
| Profiles | 11 | `profiles/*.json` |
| CI jobs in `ci.yml` | 20 | top-level job keys |

## Pinned profile denominators

Cycle 023 adds no property and no profile (DESIGN §10), so all eleven must stay
unchanged:

| Profile | Denominator |
|---|---|
| mcp-security-baseline | 10 |
| agentic-security-baseline-2026 | 10 |
| prompt-injection-baseline-2026 | 3 |
| tool-security-baseline-2026 | 6 |
| identity-security-baseline-2026 | 6 |
| memory-security-baseline-2026 | 6 |
| rag-security-baseline-2026 | 6 |
| mcp-auth-hardening-2026 | 10 |
| agentic-supply-chain-security-2026 | 10 |
| agentic-a2a-security-2026 | 12 |
| multi-turn-security-baseline-2026 | 7 |

## v1 attack-graph golden digests (BLUEPRINT §4.10)

The digests come from running
`dare-agent-security validate attack-graph --facts fixtures/attack-graph/<name>.json --output-dir <dir>`
with the default bounds (`--max-depth 8 --max-paths 64`), using the binary built at
`32909ea`. Every run exited 0. Each value is the SHA-256 of the file bytes.

| Fixture | `attack-graph.json` | `paths.json` |
|---|---|---|
| auth-mutation | `3a20f568f797865f3f04b202289a686c3e4d157b8c7d38017de1f0669d220c1d` | `2ade4af40b9aea3d1232bbde837dc585afeb64889dafab47a98f835ef5f67bf3` |
| blocked-destructive | `946b473e217122750d98382343e685886c0e741fb5acf6abad4a2979c1663368` | `68b19c5d50e6a625afc2f5c2d650999c2051b4e7f0b31cae5be5dcff5fba9049` |
| confused-deputy | `e7115fdda69858de6a2b5ac13f464fa7c334db69b59a37879bba2667c5459d40` | `9738dd799937d46b813a9237188dba09c3d50651b8939043a37db45c77bb69aa` |
| inferred-credential | `2ebd980b199f7da5044965274bbece2ea7c701654f2faea8fc79454cbc6bcb1d` | `3ff54b10ed6bbc1ed05648d064daa7ba1fd559f281e42170cdbf1171330ad59e` |
| safe-read | `910c73ab010caeaed784b9f4d125917215230f082e630a6bbb0542286b3d315a` | `d9c34582b567516de250e23e5e2beaa7a692d0d3a9b298217595b0eeb0ccc04a` |

`crates/dare-attack-graph/tests/v1_unchanged.rs` (task-002) asserts these digests.

## Defect to correct in v1 (Design §4.9 item 1)

- `crates/dare-attack-graph/src/path.rs:140` calls `.unwrap()` in production code, inside
  `make_path`.

## Observations, out of scope (BLUEPRINT §13, Design Q6)

These are recorded for the separate hotfix. Cycle 023 does not change them.

| # | Observation | Location |
|---|---|---|
| O-1 | Four evidence bridges cite `https://darelabs.tech/schemas/evidence/v1/security-evidence.schema.json`, which does not exist. The schema on disk is `…/evidence/v1/evidence.schema.json`. Separately, only `schemas/multi-turn-security/v1/result.schema.json` and `schemas/remote-validation/v1/result.schema.json` exist, while nine engines set a `RESULT_SCHEMA_ID` | `dare-a2a-security/src/evidence_bridge.rs:33`, `dare-mcp-auth-security/src/evidence_bridge.rs:32`, `dare-supply-chain-security/src/evidence_bridge.rs:32`, `dare-multi-turn-security/src/evidence_bridge.rs:27`; `RESULT_SCHEMA_ID` in each engine's `src/result.rs` |
| O-2 | `A2aEvidence::card_for` matches `card.card_id == peer_id`, while its doc comment says it matches "by the peer's own `card_id` reference" | `dare-a2a-security/src/normalize.rs:73-77` |
| O-3 | The 019 result gives manifest, provenance and attestation files no per-file digest (`DocumentRecord` covers CycloneDX and SPDX only). `evidence_digest` is their only pin | `dare-supply-chain-security/src/result.rs` (`documents`, `evidence_digest`) |
| O-4 | The tool engine builds `event_digests` with `filter_map(\|event\| event.digest().ok())`, so an event whose digest fails is silently dropped and `event_digests[i]` can stop lining up with `events[i]` | `dare-tool-security/src/result.rs:323-326` |

## GitHub Action image

- The Cycle 022 hotfix PR (#47), whose head tree equals this baseline, merged with every
  check green, `Action E2E (*)` included (Product Owner confirmation, 2026-09-28). That
  run is the authoritative image check for the baseline.
- A local builder-stage `docker build` runs again in task-044, after the changes.
