# Cycle 022 — Baseline

**Status:** DONE  
**Measured on:** 2026-09-28  
**Baseline commit:** `main @ b6f14b9` (merge of PR #45). Its tree (`6011b965…`) is identical to the Cycle 021 closing commit `4d691d1`, verified with `git rev-parse 4d691d1^{tree} b6f14b9^{tree}`.

Every later claim about what Cycle 022 added or changed is a difference against these measured numbers.

## Workspace

| Measure | Value | How measured |
|---|---|---|
| `cargo test --workspace` result suites | 280 | count of `test result:` lines |
| Tests passed / failed / ignored | 3 955 / 0 / 3 | sum over those lines |
| Workspace members | 21 | `Cargo.toml` `[workspace].members` |
| Registry v2 properties | 65 | `schemas/coverage/v2/registry.json` |
| Profiles | 11 | `profiles/*.json` |
| CI jobs in `ci.yml` | 19 | top-level job keys |

## Pinned profile denominators

These are the literals in `crates/dare-coverage/tests/multi_turn_profile.rs::no_earlier_profile_denominator_moved`,
plus the Cycle 021 profile. Cycle 022 adds no property and no profile (DESIGN §10), so all
eleven must stay unchanged.

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

## GitHub Action image

- In this session, the builder stage of the root `Dockerfile` was built with
  `docker build --target builder` on the same tree (recorded in Cycle 021
  `EXECUTION/task-035.md`). It compiled the whole workspace in release inside the image,
  and the in-image binary ran `validate multi-turn` correctly with networking disabled.
- The runtime stage's `apt-get` cannot run here, because the session network policy
  denies `deb.debian.org`. `action-e2e.yml` on the pull request is the authoritative
  check of the full image.
- Directories copied by the `Dockerfile`: `crates`, `labs`, `schemas`, `vectors`,
  `profiles`, `standards`, `integrations`, `benchmark`, `fixtures`. Cycle 022 embeds only
  from `schemas/remote-validation/v1/` (BLUEPRINT AD-16).

## Evidence-bridge defect confirmed at baseline

| Bridge | Lines | INCONCLUSIVE/ERROR `observed.decision` | Validated before return |
|---|---|---|---|
| a2a | `evidence_bridge.rs:234-243` | `Some(NotApplicable)`, a mismatch against `expected = Deny` | no |
| mcp-auth | `evidence_bridge.rs:219-228` | `Some(NotApplicable)` | no |
| supply-chain | `evidence_bridge.rs:215-224` | `Some(NotApplicable)` | no |
| identity, memory, rag, prompt-injection, tool | — | `None` | no |
| multi-turn | — | `None` (result keeps a string) | no |

No engine bridge calls `dare_security_evidence::validate` in production code. They call
only `validate_secret_safety`.

Three existing tests pin the defective value:
- `dare-a2a-security/src/evidence_bridge.rs:438`
- `dare-mcp-auth-security/src/evidence_bridge.rs:472`
- `dare-supply-chain-security/src/evidence_bridge.rs:426-431`

## Protocol versions (task-041 input)

A2A `1.0.0` (Cycle 020) and MCP `2026-07-28` (Cycle 018), recorded in
`standards/remote-validation/2026/provenance.json`.
