# One-command demo

```bash
./demo/run-demo.sh                 # writes demo-output/REPORT.md and demo-output/report.html
./demo/run-demo.sh --output-dir x  # another (relative) directory
```

Runs in about two seconds once the binary exists. It is fully offline: every input
is a synthetic lab shipped in this repository, and no network, real target or
credential is used.

**Requirements:** a checkout of this repository, `python3` (standard library only,
for the report), and either `dare-agent-security` on `PATH`, `DARE_BIN` pointing at
it, or `cargo` (the script then builds it on first run). `SYNTHETIC_MCP_BIN` overrides
where the synthetic MCP server is found. On Windows, run it under WSL.

## The story

| Act | What runs | What the audience sees |
|---|---|---|
| 0. Inventory | `discover` on the synthetic MCP server | the agent's 8 tools by class, including one destructive tool |
| 1. Before | `rag-security` ×2 and `identity-security` on ATTACK-PATH-LAB APL-001, then `attack-paths` and `blast-radius` | 3 failed checks that combine into 4 attack paths: an uploaded document steers the assistant to an index admin credential and to another tenant's document |
| 2. After | the same engines on APL-002, the control twin with the controls fixed | 0 failed checks, every path `CONTROLS_HELD`, 0 exposed targets |
| 3. Runtime | `runtime-telemetry` on two recorded OTLP traces | the attack trace (unauthorized tool call) is FAIL, the clean trace PASS |

The report also names the **chokepoints**: the one control whose fix closes several
paths at once. That's the remediation priority a security team gets from the tool.

Every step has an expected exit code. When a step ends differently, the script stops
and points at `steps.log`, so a presenter never shows a result nobody has verified.
`crates/dare-agent-security-cli/tests/demo_kit.rs` runs the demo in CI and pins the
story (4 paths, 4 exposed pairs before; 0 after; FAIL then PASS at runtime).

## Output

| File | Content |
|---|---|
| `REPORT.md`, `report.html` | the consolidated report (the HTML is self-contained: no script, no remote resource) |
| `demo-summary.json` | the figures the report shows, as data |
| `0-inventory/`, `1-before/`, `2-after/`, `3-runtime/` | every engine's own artifacts, evidence and summary |
| `steps.log` | each command's output and exit code |

The script deletes an existing output directory only when it wrote it itself (a
`.dare-demo-output` marker); any other non-empty directory is refused.

## What it does not claim

Everything is synthetic. `PASS` and `CONTROLS_HELD` mean the controls on the
enumerated paths were observed to hold in these runs, not that a system is secure.
See the last section of the report.
