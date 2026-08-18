# DARE Agent Security — 90-Day Roadmap

This roadmap is intentionally narrow. The objective is to validate the need for deterministic MCP/agent security testing before expanding into a broader platform.

## Days 1–30 — Implementer

Goal: ship a useful open-source security baseline and enter upstream standards discussions with working code.

Deliverables:

- CLI skeleton and stable command conventions;
- MCP server/tool discovery;
- non-intrusive enterprise security baseline;
- versioned evidence schema;
- AuthZEN / COAZ-MCP mapping layer;
- initial deterministic conformance vectors;
- OWASP Agentic Security mappings;
- synthetic vulnerable MCP lab;
- GitHub Action proof of concept;
- first upstream AuthZEN/COAZ-MCP contribution or substantive implementation feedback.

Candidate first standards work:

- authorization-to-execution integrity;
- principal vs. acting-agent identity binding;
- negative conformance vectors around tool/method/argument mutation after authorization.

## Days 31–60 — Researcher

Goal: turn implementation work into reproducible public research.

Deliverables:

- benchmark harness;
- documented sampling and methodology;
- false-positive review process;
- reproducible static analysis of public MCP repositories;
- first security benchmark release candidate;
- technical articles derived from the implementation work;
- basic agent/tool/resource attack graph.

Do not publish headline vulnerability percentages until sampling, methodology, versioning, and false-positive treatment are documented.

## Days 61–90 — Company

Goal: validate willingness to use and pay for continuous agent security validation.

Targets:

- 20 AppSec / Product Security / IAM conversations;
- 10 real evaluations across authorized environments where feasible;
- 3 design-partner candidates;
- 1 paying customer or paid pilot target;
- 1 accepted or materially advanced standards contribution;
- 1 external open-source contributor;
- CI integration used by at least one real MCP project.

## Product progression

```text
Phase 1  Agent / MCP Scanner
             |
             v
Phase 2  Deterministic Adversarial Testing
             |
             v
Phase 3  Agent Attack Graph
             |
             v
Phase 4  Continuous Agent Security Validation
             |
             v
Phase 5  Enterprise Agent Security Platform
```

Phase 5 is deliberately out of scope until earlier phases demonstrate real adoption and customer demand.
