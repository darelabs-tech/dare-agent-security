# External-operator usability checklist (Cycle 011 task-024)

Evidence that an operator unfamiliar with Cycles 001–010 can complete the product journey.

| Step | Evidence |
|------|----------|
| Install / version | `docs/product/packaging-install.md`, `dare-agent-security --version` |
| Doctor | `doctor` command + CLI test `product_cli.rs` |
| Init | `init` creates `.dare-security/config.yaml` |
| Assess vulnerable | `examples/vulnerable-mcp` + quickstart |
| Read executive/technical HTML | `reports/*.html` under run dir |
| Apply remediation | `examples/vulnerable-mcp/REMEDIATION.md` |
| Reassess secure | `examples/secure-mcp` expects PASS |
| Confidential/offline | flags + `privacy-mode.json` evidence marker |
| Docs | `docs/quickstart.md`, `docs/product/*` |

Operator notes: categorized errors (`[configuration]`, etc.) and EXIT.md product section.
