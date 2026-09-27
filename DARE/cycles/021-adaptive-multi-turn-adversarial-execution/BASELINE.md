# Cycle 021 — Baseline

**Status:** DONE  
**Measured on:** 2026-09-27  
**Baseline commit:** `main @ 4ca06b2` (merge of PR #44), verified with `git merge-base --is-ancestor 4ca06b2 HEAD`

Every later claim about what Cycle 021 added is a difference against these measured numbers.

## Workspace

| Measure | Value | How measured |
|---|---|---|
| `cargo test --workspace` result suites | 264 | count of `test result:` lines |
| Tests passed / failed / ignored | 3 767 / 0 / 3 | sum over those lines |
| Workspace members | 20 | `Cargo.toml` `[workspace].members` |
| Registry v2 properties | 58 | `schemas/coverage/v2/registry.json` |
| Profiles | 10 | `profiles/*.json` |
| CI jobs in `ci.yml` | 18 | top-level job keys |

Registry properties by risk family: AGENTIC_SUPPLY_CHAIN 10, AGENT_GOAL_HIJACKING 4,
CASCADING_FAILURES 2, HUMAN_AGENT_TRUST_EXPLOITATION 2, IDENTITY_PRIVILEGE_ABUSE 6,
INSECURE_INTER_AGENT_COMMUNICATION 12, MEMORY_CONTEXT_POISONING 6, ROGUE_AGENTS 2,
TOOL_MISUSE_EXPLOITATION 6, UNEXPECTED_CODE_EXECUTION 2.

None of the seven Cycle 021 property IDs (DESIGN §4.1) exists in the registry yet.

## Pinned profile denominators

These are the literals in `crates/dare-coverage/tests/a2a_profile.rs::no_earlier_profile_denominator_moved`.
Cycle 021 must leave all nine unchanged.

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

## GitHub Action image (Blueprint AD-10)

- **Local build: not possible in this environment.** `dockerd` started, but
  `docker build .` failed while resolving `debian:bookworm-slim` and
  `rust:1.88-bookworm`: Docker Hub answered `429 Too Many Requests`. A retry 30 s later
  failed the same way. This is a registry rate limit, not a repository defect.
- **Fallback evidence (allowed by the task-001 criterion):** the latest `action-e2e`
  run, [36339198428](https://github.com/darelabs-tech/dare-agent-security/actions/runs/36339198428),
  concluded `success` on `9977c5c`. The only difference between `9977c5c` and the
  baseline `4ca06b2` is the `Cargo.lock` bump of `rustls` 0.23.43 → 0.23.45 and
  `chacha20` 0.10.1 → 0.10.2 (commit `72b5c8b`). That bump compiled and passed
  `cargo test --workspace` locally, but it has **not** been built into the image. The
  Phase 10 container check (task-035) must therefore build the image on a head that
  includes it.
- **Directories copied by the root `Dockerfile`:** `crates`, `labs`, `schemas`,
  `vectors`, `profiles`, `standards`, `integrations`, `benchmark` and `fixtures`.
  Existing `include_str!` targets already resolve under `schemas/`, `standards/`,
  `profiles/`, `integrations/`, `benchmark/` and `fixtures/`, and the new crate must
  stay within this set.

## Scope reminder

No Cycle 021 code exists at this baseline. The planning artifacts on the execution
branch are `DESIGN.md`, `APPROVAL.md`, `BLUEPRINT.md`, `TASKS.md`, `dare-dag.yaml` and
`dare-dag.exec.yaml`.
