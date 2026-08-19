# task-010 — `dare-agent-security discover` CLI

> Status: DONE
> Depends on: task-005, task-006, task-007, task-008
> Complexity: HIGH

## Objective
Deliver the first usable CLI surface for passive MCP discovery.

## Commands
```bash
dare-agent-security discover --stdio -- <command> [args...]
dare-agent-security discover --url <https-url>
dare-agent-security discover ... --json
```

## Required behavior
- stdio and URL modes mutually exclusive;
- explicit target only;
- human-readable baseline by default;
- `--json` writes canonical Inventory v1 JSON only to stdout;
- diagnostics to stderr;
- stable documented exit semantics;
- bounded options for timeout/pages/items;
- optional evidence output directory;
- no raw credential/token/password flags.

## Security invariants
No shell interpolation for stdio target. No redirect-based scope expansion. Refused/unsupported operations return non-zero. Secrets never appear in CLI output.

## Tests
Argument conflicts, JSON-only stdout, human summary, stderr separation, stable exit codes, stdio/HTTP synthetic target, partial and unsupported target paths.

## DONE when
The CLI discovers the synthetic lab through supported transports and produces deterministic human/JSON results while respecting all safety boundaries.
