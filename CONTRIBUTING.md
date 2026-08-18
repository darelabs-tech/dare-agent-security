# Contributing to DARE Agent Security

Thank you for contributing to DARE Agent Security.

The project values small, reviewable, reproducible contributions that improve the security of AI-agent and MCP ecosystems.

## Contribution principles

Contributions should prefer:

- deterministic security assertions over subjective LLM-only judgments;
- reproducible evidence over screenshots or anecdotal claims;
- standards-backed mappings over proprietary taxonomies;
- safe-by-default behavior for active testing;
- synthetic fixtures over customer-derived confidential data;
- focused pull requests with tests and clear threat models.

## Standards references

When a contribution implements or validates a standards requirement, reference the relevant upstream material in the pull request and, when practical, in the test metadata.

Examples include:

- Model Context Protocol specifications;
- OpenID AuthZEN;
- COAZ / COAZ-MCP;
- OWASP Agentic Security guidance;
- OAuth/OIDC requirements;
- CWE identifiers.

Do not imply upstream endorsement merely because a mapping exists.

## Security test vectors

A new security test vector should define, at minimum:

1. a stable identifier;
2. the security property being tested;
3. preconditions;
4. input or mutation;
5. expected deterministic outcome;
6. observed outcome format;
7. evidence artifacts;
8. severity rationale where applicable;
9. standards mappings where applicable;
10. a safe synthetic fixture or mock target.

Example conceptual result:

```text
Vector:   COAZ-MCP-PERMIT-INTEGRITY-001
Expected: RE-EVALUATE
Observed: ALLOW
Result:   FAIL
```

## Customer and third-party data

Do not contribute:

- customer source code;
- credentials or tokens;
- private URLs or endpoints;
- confidential MCP schemas;
- internal logs or traces;
- unpublished vulnerability details from third parties;
- proprietary reports or evidence.

If a real assessment exposes a useful vulnerability class, create a sanitized, synthetic reproduction before proposing it upstream.

## Active and offensive capabilities

Active testing functionality must be designed for authorized environments. New state-changing, intrusive, destructive, or high-load behavior should:

- be disabled by default;
- require explicit operator intent;
- support scope enforcement;
- be auditable;
- include resource/rate safeguards;
- provide deterministic stop conditions where practical.

## Developer Certificate of Origin

By contributing, you certify that you have the right to submit the contribution under the project's Apache-2.0 license.

Commits should include a Developer Certificate of Origin sign-off:

```bash
git commit -s -m "feat: add COAZ-MCP conformance vector"
```

This produces a `Signed-off-by:` line in the commit message.

See https://developercertificate.org/ for the DCO text.

## Pull requests

A pull request should explain:

- the problem or security property;
- the implementation approach;
- how it was tested;
- relevant standards/issues;
- any compatibility or safety impact.

Keep unrelated refactors out of security-vector PRs whenever possible.

## Reporting vulnerabilities in DARE Agent Security

Do not report vulnerabilities in this project through a public issue. Follow [SECURITY.md](SECURITY.md).

## Upstream standards contributions

Contributing code here does not automatically satisfy contribution requirements of standards organizations. For example, OpenID Foundation working groups may require separate intellectual-property contribution agreements before filing issues or submitting specification changes. Follow each upstream project's own contribution rules.
