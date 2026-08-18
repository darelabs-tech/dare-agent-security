# task-010 — Implement `dare-agent-security discover` CLI

## Goal
Expose Cycle 002 as a usable CLI surface for developers and security engineers.

## Required implementation
- `dare-agent-security discover --stdio -- <command> [args...]`.
- `dare-agent-security discover --url <https-url>`.
- Input modes mutually exclusive.
- `--json` emits only canonical inventory JSON to stdout.
- Human mode emits deterministic baseline counts/classification summary.
- Diagnostics go to stderr.
- Implement `--target-id`, timeout/page/item bounds and optional evidence output path.
- No raw password/token/API-key flags.
- Exit codes: 0 complete, 2 valid partial, 3 target/protocol failure, 4 local policy refusal.

## Required tests
CLI argument conflicts; help; complete human output; JSON parse/contract validation; partial exit 2; protocol failure exit 3; policy refusal exit 4; stdout purity in JSON mode.

## Gates
Standard workspace gates.

## DONE
A user can inventory the synthetic target in human or machine mode and automation can rely on stable exit/output contracts.