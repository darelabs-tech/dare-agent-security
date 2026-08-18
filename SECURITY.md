# Security Policy

## Supported versions

DARE Agent Security is currently pre-alpha. Until the first stable release, only the latest commit on the default branch is considered supported for security fixes.

## Reporting a vulnerability

Do **not** open a public GitHub issue for vulnerabilities in DARE Agent Security.

Report security issues privately to the DARE Labs maintainers using a private communication channel agreed with the maintainers. Include, when possible:

- affected version or commit;
- impact and threat model;
- reproducible steps;
- proof-of-concept limited to the minimum necessary to demonstrate impact;
- suggested remediation;
- whether exploitation has been observed in the wild.

Please avoid including secrets, production data, customer data, or third-party confidential information in a report.

## Authorized testing only

This project is intended for defensive validation, research, conformance testing, and assessments of systems for which the operator has explicit authorization.

Before running active or adversarial tests against any environment, confirm:

- written authorization and approved scope;
- target environments and assets;
- allowed and prohibited actions;
- data handling and retention requirements;
- rate and resource limits;
- approval requirements for state-changing actions;
- rollback and kill-switch procedures;
- incident and escalation contacts.

Default to local, sandbox, or staging validation before production testing.

## Safe defaults

Contributions that add active testing capabilities should be safe by default. Destructive or state-changing actions must require explicit opt-in and should support deterministic scope checks, approval gates, budgets, and auditable evidence.

The project must not silently expand scope, bypass authorization, reuse credentials outside their intended context, or treat model output as authority to override deterministic security policy.

## Customer confidentiality

Never commit customer source code, non-public endpoints, credentials, architecture diagrams, logs containing sensitive data, proprietary MCP schemas, vulnerability details, or private assessment evidence to this repository.

When a real-world vulnerability pattern is useful to the community, create a sanitized synthetic reproduction that preserves the security property without exposing the affected organization.
