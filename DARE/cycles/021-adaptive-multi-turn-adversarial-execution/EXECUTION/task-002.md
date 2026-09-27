# task-002 — Record multi-turn standards provenance snapshot

**Status:** DONE  
**Complexity:** LOW

## Files changed

- `standards/multi-turn-security/2026/provenance.json` (new)

## Result

The file records five sources: OWASP ASI01, ASI03, ASI06 and ASI09 as NORMATIVE risk
taxonomy, and OWASP LLM01 as an INFORMATIVE delivery technique. The `canonical_reference`
strings are copied exactly from `schemas/coverage/v2/registry.json`, and the LLM01
source id `OWASP_LLM_TOP10_2025` matches Cycle 013's provenance. The file also records
seven property mappings (I01–I07) and the scopes deferred to Cycles 022–025. It carries
the fetch policy, re-verification note, conformance disclaimer and status discipline in
the same form as Cycle 020. The JSON parses (`python3 -c "import json; json.load(...)"`).

The file is not embedded yet. When a later task embeds it, it sits under `standards/`,
which the Action image's `Dockerfile` copies (Blueprint AD-10).

## Ralph Loop

- Build: `cargo build --workspace` green
- Test: `cargo test --workspace`: 266 suites, 3 781 passed, 0 failed (baseline 3 767 + 14 new)
- Lint: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` green
- Audit: `cargo audit` clean. No external dependency was added; `Cargo.lock` gains only the new workspace member.
