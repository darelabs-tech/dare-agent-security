# task-039 — Build the ATTACK-PATH-LAB harness and scenarios APL-001..APL-012

**Status:** DONE  
**Complexity:** HIGH

## Harness (`crates/dare-agent-security-cli/tests/attack_path_lab.rs`)

For each `tests/fixtures/attack-path-lab/APL-NNN/` directory, the harness does the following:

1. It runs every engine run listed in `lab.json` through the real binary
   (`CARGO_BIN_EXE_dare-agent-security`, working directory = repository root, so built-in
   ids resolve as in CI) and requires engine exit 0 or 2.
2. It copies the engine inputs into `run-<i>/inputs/`:
   - the shipped scenario file for tool, identity, memory, RAG and MCP Auth;
   - `scenario.json` plus `evidence/` for static supply-chain.
3. It computes each run tag with `RunTag::from_result_bytes` and substitutes `${run:N}` in
   `system-model.json` and `expected.json`.
4. It runs `validate attack-paths` twice, the second time with the artifacts reversed.
   The exit code and all six files must be byte-identical (O-06).
5. It compares with `expected.json`:
   - the exit code;
   - each expected path by node ids, with its control state, entry and target class and
     the **exact** set of failed properties;
   - the `absent` paths, which appear neither feasible nor discontinuous;
   - the `discontinuous` paths, with `discontinuity_at`;
   - `no_failed_property`;
   - chokepoints, which must lie on feasible paths;
   - node ids, artifact provenance, `unprojected` counts and summary text.

**O-01 (no hand-written facts).** A scenario directory may hold only the following:
- engine scenarios, and engine evidence documents;
- the system model;
- the expectation.

The harness also enforces two rules:
- a file name that looks like graph input (`facts`, `attack-graph`, `paths`) fails;
- `declared_edges` in a model is allowed only where `lab.json` sets `declared_edges: true`.

`generate.py` writes all scenario directories; `README.md` documents the layout and classes.

## Scenarios APL-001..012

| Id | Class | Role | Runs | Expected |
|---|---|---|---|---|
| APL-001 | A | attack | RAG-LAB-014, RAG-LAB-002, IDENTITY-LAB-006 | document → alice → tenant-B document FAILED (CONTENT_TRUST_BOUNDARY, TENANT_DOCUMENT_ISOLATION); document → alice → credential FAILED (CONTENT_TRUST_BOUNDARY, PRIVILEGE_AMPLIFICATION) |
| APL-002 | A | control | RAG-LAB-013, RAG-LAB-001, IDENTITY-LAB-019 | document → alice → credential CONTROLS_HELD; cross-tenant path absent; exit 0 |
| APL-003 | A | NOT_TESTED | RAG-LAB-014, RAG-LAB-002 | credential path absent |
| APL-004 | A | variant | RAG-LAB-014, IDENTITY-LAB-019 | handbook → alice → credential UNDECIDED (ENTITY-scope narrowing) |
| APL-005 | B | attack | MEMORY-LAB-008, MEMORY-LAB-004, IDENTITY-LAB-006 | mallory → tenant-B memory → alice → credential FAILED (WRITE_TRUST_BOUNDARY, PRIVILEGE_AMPLIFICATION); alice → tenant-B memory FAILED (TENANT_BOUNDARY) |
| APL-006 | B | control | MEMORY-LAB-007/003/001/009, IDENTITY-LAB-019 | both attack paths absent; alice → credential HELD |
| APL-007 | B | NOT_TESTED | MEMORY-LAB-008, MEMORY-LAB-004 | credential path absent |
| APL-008 | B | attack | MEMORY-LAB-010, MEMORY-LAB-002, IDENTITY-LAB-019 | FAILED (PROVENANCE_INTEGRITY); FAILED (RECALL_AUTHORITY_BOUNDARY) |
| APL-009 | C | attack | A2A-LAB-016, IDENTITY-LAB-004 | peer → assistant → index service → credential FAILED (SKILL_AUTHORIZATION) |
| APL-010 | C | control | A2A-LAB-010, IDENTITY-LAB-004 | same path UNDECIDED |
| APL-011 | C | NOT_TESTED | A2A-LAB-016 | path absent; exit 0 |
| APL-012 | C | attack | A2A-LAB-011, IDENTITY-LAB-004 | FAILED (PEER_IDENTITY_BINDING, SKILL_AUTHORIZATION) |

These chain classes differ from the Blueprint table as recorded in REGRESSION R-16 and R-17.
They were designed after running every shipped LAB scenario of every engine and reading
what each projects (142 simulated runs, plus 80 A2A and supply-chain runs).

## Ralph Loop

Green: fmt, clippy `-D warnings --tests`, the lab test and the full CLI test suite. No
dependency was added. `dare-attack-path` is already a normal dependency of the CLI, and
the lab uses its public `RunTag`.
