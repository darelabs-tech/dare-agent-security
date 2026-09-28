# task-038 — Add the `remote-validation-2026` CI job

**Status:** DONE  
**Complexity:** LOW

## Files changed

- `.github/workflows/ci.yml`: the `remote-validation-2026` job, before `docs-build`. The trigger is unchanged (`pull_request` / `types: [opened]`).
- `scripts/k22/assert_no_real_credentials.py`: derived from k21, with Cycle 022 file lists. It covers the remote crate's shipping sources, the CLI module, `observed.rs`, the remote tests, the schemas and the CLI replay fixture.
- `scripts/k22/verify_proof_citations.py`: derived from k21, with Cycle 022 paths and a function allowlist.

## Job steps

1. Unit tests
2. Lab harness
3. Gateway, proxy, window and egress
4. Rate, budget and authorization refusals
5. Protocol clients
6. Live equals offline: `engines_live`, `a2a_live`, `mcp_auth_live`, and the 018 `observed` unit tests
7. Runner, REMOTE-LAB and replay equivalence
8. `every_bridge_validates`
9. Compatibility
10. CLI process boundary
11. The credential and endpoint sweep
12. PROOF citations
13. **Offline CLI**, twice:
    - `replay-capture` on the committed fixture: exit 2, five files, `cmp` equal to `expected-result.json`, and `assert-json` on the verdict fields;
    - `validate remote` confirming another origin: exit 3, and the output directory does not exist.

## Verification

- The YAML parses. The job list ends `multi-turn-security-2026`, `remote-validation-2026`, `docs-build`.
- Both offline CLI steps were run locally with the job's own commands: exit 2, `identical`, `assert=0`; then exit 3, `nothing-written`.
- `python scripts/k22/assert_no_real_credentials.py` exits 0 over 33 shipping files, 19 test files and 12 artifacts. It first flagged a test's `WWW-Authenticate` value (`Bearer resource_metadata=…`) as a bearer-token shape; the test now uses `Bearer realm="lab"`.
- `verify_proof_citations.py` runs in task-043, once `PROOF.md` exists.
