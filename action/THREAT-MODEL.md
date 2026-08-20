# GitHub Action threat model (Cycle 004)

**Scope:** Docker container Action adapter for `dare-agent-security`  
**Assumption:** Workflow runs in a repository context where PR authors may control files, workflow inputs, and MCP metadata surfaced to the scanner.

## Assets

- Repository source and workflow configuration
- `GITHUB_TOKEN` (read-only in recommended configuration)
- CI secrets available to the workflow (must not appear in logs/outputs)
- Operator-defined MCP targets (stdio commands, URLs)

## Trust boundaries

```text
[Untrusted PR content]  -->  [Action inputs]  -->  [Entrypoint shell]  -->  [CLI]  -->  [Evidence JSON]
                                      |                      |
                                      v                      v
                              GITHUB_OUTPUT           GITHUB_STEP_SUMMARY
```

The entrypoint and CLI must treat everything from the left of the CLI boundary as untrusted data.

## Threats and mitigations

### T1 — Shell injection via `target` or paths

**Risk:** Metacharacters in `target`, `output-dir`, or MCP stdio command cause arbitrary command execution in entrypoint.

**Mitigations (task-005/009):**

- No `eval`, no `sh -c "$USER"`, no backtick expansion of inputs
- Pass all values as separate argv elements to `dare-agent-security`
- Validate `mode` against enum before invocation
- Reject `output-dir` containing `..` segments that escape workspace root

### T2 — Path traversal via `output-dir`

**Risk:** Attacker writes evidence or summary outside workspace.

**Mitigations:**

- Canonicalize resolved path; require prefix match with `/github/workspace`
- Refuse absolute paths outside workspace even if syntactically valid

### T3 — Secret leakage to logs, outputs, or summary

**Risk:** Bearer tokens, env secrets, or redacted evidence fields appear in `GITHUB_OUTPUT`, `GITHUB_STEP_SUMMARY`, or stdout.

**Mitigations:**

- Entrypoint must not `env | sort` or dump environment
- CLI redaction kernel (Cycle 001) remains active for evidence
- GitHub outputs carry only verdict tokens and relative paths — never raw MCP payloads
- Job summary uses structured fields; no raw request/response bodies (BLUEPRINT § Job summary)
- Task-009 tests with accidental secret strings in fixtures

### T4 — Malicious MCP metadata

**Risk:** Attacker-controlled MCP tool names, descriptions, or JSON fields trigger execution or scope expansion.

**Mitigations:**

- CLI passive policy (Cycle 002) — no execution of discovered tool names
- No dynamic dispatch from MCP metadata in Action layer
- Explicit target only — no host enumeration or redirect following beyond engine-approved behavior
- Unsupported protocol revisions fail closed (exit 3)

### T5 — Scope expansion

**Risk:** Action infers additional targets from repo metadata, redirects, or neighbor discovery.

**Mitigations:**

- `target` input required for discovery mode; never auto-expanded
- Action does not read `package.json`, compose files, or k8s manifests to discover endpoints
- Document “explicit target only” in operator docs (task-010)

### T6 — Mutable dependency / supply-chain risk

**Risk:** Action downloads moving binary or unpinned third-party actions at runtime.

**Mitigations:**

- CLI compiled from same commit as `action.yml` — no curl-pipe installers
- Document pin-by-SHA for consumers
- Pin third-party actions in hardened examples when practical
- No unnecessary third-party actions inside implementation

### T7 — INCONCLUSIVE interpreted as success

**Risk:** Ambiguous evidence silently passes CI.

**Mitigations:**

- Aggregate precedence preserves `INCONCLUSIVE` distinct from `PASS` (task-002)
- Default `fail-on-inconclusive: true` → exit 2
- Contract tests prove no silent PASS mapping

### T8 — Markdown/control-character injection in summary

**Risk:** MCP metadata breaks out of summary formatting or hides verdict.

**Mitigations:**

- Sanitize/escape user-controlled strings in summary rendering (task-006)
- Task-009 tests with control characters and markdown metacharacters in target metadata

## Out of scope (explicit non-goals)

- Active adversarial mutation against production targets
- `pull_request_target` with write token
- GitHub Check Runs or PR comment APIs
- SARIF upload

## Verification matrix (task-009)

| Case | Expected behavior |
|------|-------------------|
| `target='; rm -rf /'` | Treated as literal target string; no shell execution |
| `output-dir='../../etc'` | Rejected or clamped to workspace |
| Unknown `mode` | Validation error, non-zero exit |
| Secret-like string in target | Not echoed to GITHUB_OUTPUT |
| Redirect to new host (if applicable) | Fail closed per CLI policy |

## Decision record

**Packaging:** Docker container Action — reproducible, no consumer Rust dependency, aligns with Rust workspace build.

**Alternative rejected:** composite + external binary — fails T6.

See `action/ARCHITECTURE.md` for build and metadata details.
