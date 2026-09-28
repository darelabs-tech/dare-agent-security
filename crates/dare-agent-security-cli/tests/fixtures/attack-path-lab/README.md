# ATTACK-PATH-LAB (Cycle 023, BLUEPRINT §8.1)

`tests/attack_path_lab.rs` runs every `APL-NNN` scenario end to end through the real
binary:

1. It runs each engine run in `lab.json` (`validate <engine> …`) from the repository root.
2. It copies the engine inputs into `inputs/`.
3. It runs `validate attack-paths` twice, the second time with the artifacts in reverse
   order, and requires byte-identical output.
4. It compares `attack-paths.json` with `expected.json`.

## Files per scenario

| File | Content |
|---|---|
| `lab.json` | chain class, role (`attack`, `control`, `not_tested`, `variant`, `structural`) and engine runs |
| `system-model.json` | entities, aliases, designations; `declared_edges` only where `lab.json` sets `declared_edges: true` |
| `expected.json` | exit code, expected paths by node ids (with `control_state` and the exact failed properties), `absent` and `discontinuous` paths, `no_failed_property` for control twins |
| `supply-chain/` | static-mode BOM, manifest and scenario (class D only) |

Nothing here is a graph fact: nodes, edges and guards come from the engines. The runs
use the engines' own shipped LAB scenarios, in their default mode (`simulated`, or
`static` for the supply-chain BOMs), and the 022 replay fixture. `${run:N}` stands for
the run tag of run N, the first 12 hex digits of the SHA-256 of its result file. It is
used for nodes that no alias names.

`generate.py` writes every scenario directory. Edit it, not the JSON, and run it again.

## Chain classes

| Class | Chain | Engines | Scenarios |
|---|---|---|---|
| A | retrieved document → acting principal → cross-tenant document or privileged credential | 017, 015 | 001 attack, 002 control, 003 NOT_TESTED, 004 INCONCLUSIVE narrowing |
| B | memory written by one principal → recalled by another → privileged credential; cross-tenant recall | 016, 015 | 005 attack, 006 control, 007 NOT_TESTED, 008 attack |
| C | peer agent → assistant → delegated service identity → privileged credential | 020, 015 | 009 attack, 010 control, 011 NOT_TESTED, 012 attack |
| D | package → dependent build → (declared) assistant → service identity → privileged credential | 019, 015 | 013 attack, 014 control, 015 NOT_TESTED |
| E | principal → inbound MCP token → MCP server → upstream credential passthrough → MCP resource; final operation | 018, 015 | 016 attack, 017 control, 018 attack |
| F | untrusted input or cross-turn conversation → assistant → destructive tool | 013, 021 | 019 attack, 020 control, 021 attack |
| G | an access under a principal the path never acquired | 015, 014 / 020 | 022, 023: `DISCONTINUOUS` |
| H | the same local id in two engines, without and with an alias | 016, 017 | 024 no join, 025 one path |
| I | an authorized remote (022) run joined to a local run | 022, 015 | 026: `dynamic_authorized` |

`REGRESSION.md` R-16 to R-19 record where these classes differ from the Blueprint table,
and why.
