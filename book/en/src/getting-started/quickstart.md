# Quickstart

Goal: from install to your first report in under 15 minutes.

```text
Install
  ↓
dare-agent-security doctor
  ↓
dare-agent-security init
  ↓
dare-agent-security assess .
  ↓
dare-agent-security report
```

## 1. Diagnose your environment

```bash
dare-agent-security doctor
```

`doctor` checks your environment, config, privacy settings, and output paths
without touching any target. It should print `PASS` before you continue.

## 2. Initialize a project

```bash
mkdir my-agent && cd my-agent
dare-agent-security init --name my-agent
dare-agent-security doctor
```

`init` writes a local config (`dare-security.yaml` by default) and prepares
the `.dare-security/` artifact store. See [Configuration](../reference/configuration.md)
for the full schema.

## 3. Run an assessment

```bash
dare-agent-security assess . --offline
```

`--offline` denies all network/telemetry egress (fail-closed) — the safest
default while you're getting familiar with the tool. See
[Offline Mode](../privacy/offline-mode.md).

## 4. Read the report

```bash
dare-agent-security report
```

This renders (or re-renders) the executive and technical HTML reports plus
the machine-readable JSON summary under `.dare-security/runs/<run-id>/`. See
[Generated Artifacts](../reference/artifacts.md) for the full layout.

## Try it on the bundled demo targets

The repository ships two demo fixtures so you can see a `FAIL` and a `PASS`
without pointing DARE at a real system yet — see
[First Assessment](first-assessment.md) for the full walkthrough:

```bash
dare-agent-security assess examples/vulnerable-mcp --offline --confidential
dare-agent-security report --path examples/vulnerable-mcp
```

## Privacy defaults

```bash
dare-agent-security assess . --confidential --offline
```

No telemetry, no cloud upload, no external AI API call — local evidence
only. Standard mode (no flags) already has telemetry off by default;
`--confidential`/`--offline` make network egress fail-closed as well.
