# Action packaging architecture (Cycle 004)

**Status:** APPROVED for implementation (task-003)  
**Decision:** Docker container Action shipping the compiled `dare-agent-security` CLI from this repository.

## Context

Cycle 004 distributes existing deterministic security capabilities (Cycles 001–003) as a GitHub Actions gate. The Action is an adapter only — it must not duplicate discovery, integrity validation, or evidence logic.

## Evaluated options

| Option | Reproducibility | Runner deps | Build latency | Verdict |
|--------|-----------------|-------------|---------------|---------|
| **Docker container action** | Image built from pinned Action commit | Linux only (GA default) | ~2–4 min cold build | **Selected** |
| Composite action + curl binary | Depends on external URL or pre-built release | Any | Low | Rejected — supply-chain risk |
| Composite + `cargo install` | Requires Rust on consumer | Any with Rust | High on consumer | Rejected — violates “no Rust on consumer” |
| JavaScript action | Would reimplement or shell-out | Any | Low | Rejected — duplicates boundary |

## Selected architecture

```text
.github/workflows/*.yml
        |
        v
action.yml (container: Dockerfile)
        |
        v
action/Dockerfile  -->  multi-stage build  -->  dare-agent-security (release)
        |
        v
action/entrypoint.sh  -->  validate inputs, invoke CLI, write GITHUB_OUTPUT
        |
        v
dare-agent-security CLI  (discover | validate coaz-integrity)
        |
        v
{output_dir}/evidence/*.json  +  ci-result.json  +  summary.md
```

### Linux runner support

GitHub-hosted `ubuntu-latest` runners support container actions natively. This matches the primary CI target for this repository.

### Build and runtime

- **Multi-stage Dockerfile (repository root):** builder stage (`rust:1.88-bookworm`) compiles workspace release binary; runtime stage (`debian:bookworm-slim`) copies the binary, `synthetic-mcp`, built-in vectors, and entrypoint.
- **Why root Dockerfile:** GitHub Actions uses the Dockerfile directory as the build context. An `action/Dockerfile` cannot see workspace crates. `action.yml` therefore sets `image: Dockerfile` at the repository root.
- **Expected image size:** ~80–120 MB (slim runtime + static-linked or dynamically linked binary).
- **Cold build time:** dominated by `cargo build --release` for workspace members; acceptable for CI gate use when Action ref is pinned.

### Action metadata

- `action.yml` at repository root with `runs.image: Dockerfile` (also at repository root).
- Inputs: bounded `mode` enum (`discover`, `validate`), required `target`, optional `output-dir`, optional `fail-on-inconclusive`.
- Outputs: `verdict`, `evidence-path`, `summary-path` (from `ci-result.json` / task-002 contract).
- `runs.using: docker`, `runs.image: Dockerfile` (root context so crates can be compiled).
- Entrypoint: `action/entrypoint.sh`.

### Workspace and evidence mapping

- `GITHUB_WORKSPACE` mounted into container at `/github/workspace`.
- Default `output-dir`: `.dare-agent-security` (relative to workspace).
- Evidence and CI result written under workspace so callers can upload artifacts.
- Entrypoint resolves `output-dir` to an absolute path and rejects traversal outside `/github/workspace`.

### Entrypoint design

- POSIX `sh` entrypoint (not bash-specific) with strict `set -eu`.
- Passes `mode`, `target`, and flags to CLI as **quoted argv** — no `eval`, no `sh -c` with user values.
- Reads `ci-result.json` after CLI run to populate `GITHUB_OUTPUT` and `GITHUB_STEP_SUMMARY`.
- Forwards CLI exit code unless `fail-on-inconclusive: false` overrides INCONCLUSIVE (task-006).

### Immutable version relationship

- Consumers should pin `uses: org/repo@<full-commit-sha>` for high-assurance use.
- Image is built from the Dockerfile in the same commit as `action.yml` — no floating binary URL.
- Cycle 004 does **not** publish Marketplace listing or stable `v1` tag.

### Permissions

Minimum caller permissions:

```yaml
permissions:
  contents: read
```

The Action does not call GitHub APIs and does not require write tokens.

## Rejection criteria (why alternatives failed)

1. **External binary download:** violates supply-chain invariant (BLUEPRINT § Supply-chain constraints).
2. **Consumer Rust toolchain:** violates reproducibility and adoption goals for polyglot repositories.
3. **JS reimplementation:** violates “Action is adapter, not second engine”.

## Implementation tasks

| Task | Deliverable |
|------|-------------|
| 005 | `action.yml`, `action/Dockerfile`, `action/entrypoint.sh` |
| 006 | GITHUB_OUTPUT + STEP_SUMMARY integration |
| 008 | E2E workflow `uses: ./` |
| 009 | Hostile-input tests |

## References

- `docs/ci-result-contract.md` — aggregate verdict and exit semantics
- `action/THREAT-MODEL.md` — untrusted input mitigations
- `DARE/cycles/004-ci-security-gate/BLUEPRINT.md` — component boundaries
