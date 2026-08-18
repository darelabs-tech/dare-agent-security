# DARE Design — DARE Agent Security

## 1. Problem

Organizations are rapidly connecting AI agents to MCP servers, tools, APIs, data, credentials, and state-changing operations. Traditional application-security controls do not fully answer whether an autonomous agent can be manipulated into performing an action that its human principal, policy, or intended workflow did not authorize.

The emerging problem is not only whether an agent is vulnerable, but whether the complete chain remains safe:

```text
Human / Principal
      -> Agent
      -> MCP Client
      -> MCP Server
      -> Tool
      -> Credential
      -> Service
      -> Resource
```

Security teams need reproducible evidence that authorization, policy, tool use, identity binding, and execution boundaries behave as intended.

## 2. Product hypothesis

Security teams adopting MCP and autonomous agents need deterministic, standards-aligned adversarial validation that can run locally and in CI before they need a full enterprise agent-security platform.

## 3. Core proposition

**Deterministic security verification for nondeterministic AI agents.**

DARE Agent Security tests concrete security properties and produces reproducible evidence:

```text
security property
      -> controlled vector
      -> expected outcome
      -> observed outcome
      -> deterministic verdict
      -> evidence
```

The LLM may assist discovery, planning, or interpretation, but it is not the final authority for a security verdict when the property can be tested deterministically.

## 4. Primary users

Initial users:

- Application Security engineers;
- product security engineers;
- offensive security / red-team teams;
- IAM and authorization engineers;
- platform teams deploying MCP infrastructure;
- developers building MCP servers and agent runtimes.

## 5. Initial use cases

### UC-01 — Enterprise MCP security baseline

Inventory MCP servers, tools, capabilities, authorization mechanisms, and dangerous operations, then generate a security baseline without intrusive exploitation.

### UC-02 — Authorization conformance

Validate security properties derived from MCP, AuthZEN, COAZ-MCP, OAuth/OIDC, and related specifications.

### UC-03 — Deterministic adversarial validation

Run controlled security vectors against local, sandbox, staging, or explicitly authorized environments and compare expected vs. observed behavior.

### UC-04 — Agent attack paths

Build a basic graph across principal, agent, MCP, tool, credential, service, and resource relationships to identify dangerous reachability and privilege chains.

### UC-05 — CI security gate

Fail a pull request or build when a new agent/MCP change introduces a known authorization or security regression.

## 6. Initial CLI

The target pre-1.0 surface is:

```text
dare-agent-security discover
dare-agent-security validate
dare-agent-security attack
dare-agent-security graph
dare-agent-security prove
```

Exact flags and output formats remain unstable during pre-alpha.

## 7. Evidence model

Each deterministic vector should be able to emit a machine-readable record containing:

- vector identifier;
- target identity;
- preconditions;
- normalized operation;
- policy inputs where available;
- expected decision/outcome;
- observed decision/outcome;
- verdict;
- standards mappings;
- severity rationale;
- evidence references;
- timestamp and relevant version/hash metadata.

The evidence model should be suitable for local files, CI artifacts, future APIs, and enterprise ingestion.

## 8. Standards strategy

DARE Agent Security should consume and validate existing standards instead of creating an isolated risk taxonomy.

Initial alignment targets:

- Model Context Protocol;
- OpenID AuthZEN;
- COAZ framework;
- COAZ-MCP binding;
- OWASP Agentic Security guidance;
- OAuth/OIDC security requirements;
- CWE where mappings are meaningful.

Mappings must record the version/date of the upstream source where practical.

## 9. Open-source boundary

Open source under Apache-2.0:

- CLI;
- MCP discovery;
- generic parsers/adapters;
- public evidence schema;
- deterministic conformance vectors;
- synthetic vulnerable labs;
- basic attack graph;
- GitHub Action / CI integrations;
- standards mappings;
- benchmark methodology;
- reproducibility tooling.

Potentially proprietary / outside this repository:

- enterprise SaaS/control plane;
- private customer connectors;
- private findings and assessment data;
- proprietary security datasets;
- historical cross-customer intelligence;
- advanced attack-graph analytics;
- distributed continuous-validation orchestration;
- enterprise governance and compliance workflows;
- commercial integrations and managed services.

No proprietary component is automatically licensed merely because it interoperates with this repository.

## 10. Safety invariants

1. Active testing requires explicit operator intent.
2. State-changing or destructive testing is disabled by default.
3. Scope must be machine-checkable where practical.
4. The engine must not treat LLM output as authority to expand testing scope.
5. Credentials must remain constrained to their intended target/context.
6. Customer or third-party confidential data must never enter public fixtures.
7. Real-world findings used for research must be sanitized into synthetic reproductions before publication.
8. Evidence should record enough context to reproduce a verdict without exposing unnecessary secrets.

## 11. Non-goals for Phase 1

DARE Agent Security Phase 1 will **not** attempt to be:

- a replacement for Okta, Microsoft Entra, CyberArk, or other IAM systems;
- an MCP gateway or universal policy decision point;
- a complete CNAPP/ASPM platform;
- a general-purpose pentesting suite;
- a SaaS dashboard;
- a proprietary agent-risk taxonomy;
- an autonomous internet-wide exploitation platform.

## 12. First design-partner hypothesis

A real enterprise environment with multiple MCP servers can validate whether security teams find value in:

1. MCP inventory and capability discovery;
2. authorization baseline findings;
3. deterministic conformance failures;
4. attack-path visibility;
5. remediation/retest evidence;
6. CI integration.

Customer-specific tests, findings, credentials, endpoints, and architecture remain private.

## 13. Success criteria — first 90 days

Technical:

- public pre-alpha repository;
- working CLI skeleton;
- MCP discovery baseline;
- public evidence schema;
- at least 10 deterministic security/conformance vectors;
- at least one AuthZEN/COAZ-MCP contribution or substantive upstream review;
- synthetic vulnerable MCP lab;
- GitHub Action proof of concept;
- basic agent/MCP attack graph.

Market/research:

- one authorized design-partner pilot;
- at least five real MCP implementations assessed in that pilot or other authorized environments;
- at least 20 AppSec/SI conversations;
- at least three organizations expressing design-partner interest;
- first reproducible MCP security benchmark methodology;
- first public technical research article based on sanitized/generalized findings.

## 14. Strategic principle

The project should optimize for becoming a trusted independent validator of agentic systems, not for owning every identity, runtime, gateway, or policy layer.

**Do not replace the ecosystem. Verify it.**
