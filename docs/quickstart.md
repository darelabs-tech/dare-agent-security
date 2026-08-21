# Quickstart — Product v1

Install from source (clean environment):

```bash
cargo install --path crates/dare-agent-security-cli --locked
dare-agent-security --version
```

Or run without installing:

```bash
cargo run -p dare-agent-security -- --version
```

## Journey (acceptance path)

```bash
# 1. Diagnostics
dare-agent-security doctor

# 2. Assess vulnerable demo (expect FAIL)
dare-agent-security assess examples/vulnerable-mcp --offline --confidential
dare-agent-security report --path examples/vulnerable-mcp

# 3. Apply documented remediation (see examples/vulnerable-mcp/REMEDIATION.md)
# 4. Reassess secure demo (expect PASS)
dare-agent-security assess examples/secure-mcp --offline
dare-agent-security report --path examples/secure-mcp
```

Integrated workflow demo:

```bash
dare-agent-security assess examples/agentic-demo --offline --confidential
```

## Init a new project

```bash
mkdir my-agent && cd my-agent
dare-agent-security init --name my-agent
dare-agent-security doctor
# Add .dare-security/fixture/assessment.json for offline fixture mode, or use power-user validate/discover.
dare-agent-security assess . --offline
dare-agent-security report
```

## Privacy

```bash
dare-agent-security assess . --confidential --offline
```

No telemetry, no cloud upload, local evidence only.
