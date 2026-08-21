# Cycle 011 - Productization & v1.0 Release Readiness

**Status:** DESIGN READY FOR REVIEW  
**Base branch:** `main`  
**Baseline:** Cycles 001-010 delivered  
**Proposed branch:** `agent/cycle-011-productization-v1-release-readiness`  
**Approval:** PENDING

## 1. Purpose

Cycle 010 declared core feature freeze. Cycle 011 converts the core into a usable product.

No new major security subsystem belongs here.

Allowed: packaging, install, onboarding, CLI UX, config, reports, diagnostics, privacy, docs, hardening, compatibility, release automation and acceptance testing.

## 2. Product completion criterion

A user unfamiliar with the internals must be able to:

```text
install
-> initialize
-> assess an MCP/agentic project
-> understand findings and coverage
-> inspect evidence and attack paths
-> apply a fix
-> rerun
-> verify remediation
```

## 3. Primary UX

Preferred product journey:

```bash
dare-security init
dare-security assess .
dare-security report
```

The common path must not require knowledge of the internal Cycles 001-010 architecture.

Safe defaults remain static/passive/plan-only unless explicitly changed.

## 4. Confidential and offline mode

v1.0 must support internal security assessments where findings cannot leave the organization.

Required behavior:

```text
no telemetry
no cloud upload
no remote model/API dependency
local evidence only
strong automatic redaction
configurable retention
network denied or restricted by default
```

Candidate UX:

```bash
dare-security assess . --confidential --offline
```

No hidden analytics, crash upload or background egress is allowed in this mode.

## 5. Configuration v1

Create a versioned schema with clear defaults and migration behavior.

Example:

```yaml
version: '1'
project:
  name: customer-agent
assessment:
  profile: mcp-security-baseline
privacy:
  mode: confidential
  telemetry: disabled
  network: restricted
reporting:
  formats: [html, json]
```

## 6. Reporting

Required product outputs:

```text
Executive HTML
Technical HTML
Stable JSON findings
Stable JSON coverage
Attack Graph JSON
Evidence bundle
```

PDF may be added only if reliable in the release path; HTML is the primary human-readable artifact.

### Executive report

Must show scope, profile/version, Assessment Coverage, gate result, severity distribution, top findings, attack-path summary, validation status and limitations.

### Technical report

Per finding: ID, property, severity, confidence, component, evidence references, attack path, expected/observed behavior, remediation and retest status.

## 7. Confidentiality metadata

Reports support classification, distribution and publication flags, e.g.:

```yaml
classification:
  level: CONFIDENTIAL
  distribution: [security-team, target-owner]
  publication_allowed: false
```

Rendered reports visibly show the classification.

## 8. Redaction hardening

Prevent secrets and configured sensitive data from leaking through reports, diagnostics, graphs or exports.

At minimum cover tokens, auth headers, cookies, private keys, passwords, connection strings, environment secrets and configured PII fields.

Credential graph nodes use logical identity, never raw credential values.

## 9. Diagnostics and errors

Provide `dare-security doctor` or equivalent with safe checks for runtime, config, profiles, permissions, output path, privacy/network mode and dependencies.

User-facing errors should distinguish configuration, unsupported target, blocked assessment, security-gate failure, environment error and internal error. Default UX must be actionable, not a raw stack trace.

## 10. Demo environments

Provide deterministic local demos:

```text
examples/vulnerable-mcp
examples/secure-mcp
examples/agentic-demo
```

The first contains known issues; the second demonstrates remediation; the third demonstrates integrated assessment, graph, controlled validation and continuous validation.

## 11. Quickstart

The quickstart is itself an acceptance test:

```text
install -> vulnerable demo -> finding -> report -> documented fix -> reassess -> PASS
```

## 12. Stable public contract

v1.0 stabilizes:

```text
primary CLI commands
config v1
report JSON v1
documented exit codes
documented artifact layout
```

Internal module layout remains non-public.

## 13. Product output layout

Recommended shape:

```text
.dare-security/runs/<run-id>/
  summary.json
  findings.json
  coverage.json
  attack-graph.json
  validation.json
  drift.json
  evidence/
  reports/executive.html
  reports/technical.html
```

Exact paths must reconcile with current repository conventions.

## 14. Performance baseline

Measure representative assessment time, memory, report generation and incremental revalidation time. Document v1 limits; do not introduce a new scale subsystem.

## 15. Release hardening

Regression-test path traversal, symlink escape, renderer/HTML injection, output-path abuse, config injection, temporary-file leakage, archive extraction, secret leakage and offline-network escape.

## 16. Release artifacts and automation

Release candidate should include a distributable artifact/package, version, checksums, release notes, changelog, known limitations, install instructions and security policy/contact. SBOM is optional if readily available with existing tooling.

Automate build, test, package, checksum and acceptance gates.

## 17. Clean-environment acceptance

Mandatory journey:

```text
fresh container/VM
-> install release candidate
-> doctor
-> assess vulnerable demo
-> generate reports
-> apply documented remediation
-> reassess
-> expected PASS
```

No developer-local state is allowed.

## 18. Release gate

v1.0 release requires PASS for installation, diagnostics, demos, confidential/offline no-egress tests, redaction, reports, CI semantics, hardening and clean-environment acceptance.

## 19. Acceptance criteria

1. Post-Cycle-010 main reconciled.
2. Primary installation works in a clean environment.
3. Version reporting works.
4. First-run initialization works.
5. Config v1 is versioned/validated.
6. Safe defaults remain intact.
7. Unified assessment UX exists.
8. Confidential mode exists.
9. Offline mode exists.
10. Telemetry can be fully disabled.
11. Offline/confidential performs no prohibited egress.
12. Redaction covers required secret classes.
13. Executive report works.
14. Technical report works.
15. Stable machine-readable reports work.
16. Classification metadata is rendered.
17. Findings link to evidence.
18. Findings link to attack paths where applicable.
19. Remediation/retest information is surfaced where supported.
20. Doctor/diagnostics exists.
21. Errors are actionable and categorized.
22. Exit codes are stable/documented.
23. Vulnerable demo is deterministic.
24. Secure demo is deterministic.
25. Agentic demo exercises integrated workflow.
26. Quickstart works from a fresh environment.
27. v1 docs cover all public workflows.
28. Privacy/data handling is documented.
29. Performance baseline is documented.
30. Release hardening tests pass.
31. Release automation produces distributable artifacts.
32. Checksums are produced.
33. Known limitations are documented.
34. Security policy/contact is documented.
35. Clean-environment v1 acceptance passes.
36. No new major security capability was added after freeze.
37. Final DARE proof maps criteria to files/tests/results.
38. `APPROVAL.md` remains absent until explicit approval.

## 20. Post-v1 rule

After v1.0:

```text
dogfooding
-> external users
-> real assessments
-> bugs/UX/FP/FN/performance evidence
-> pilots
-> observed product pain
-> Cycle 012
```

Do not design Cycle 012 before real usage evidence exists.
