# Packaging and install (Product v1)

## Build

```bash
cargo build -p dare-agent-security --release
```

Binary: `target/release/dare-agent-security` (Windows: `.exe`).

MSRV: **1.88**. rmcp pinned at **3.1.3**.

## Install from source

```bash
cargo install --path crates/dare-agent-security-cli --locked
```

Optional shell alias: `dare-security` → `dare-agent-security`.

## Release packaging

```bash
# Unix
./scripts/release/package.sh

# Windows PowerShell
./scripts/release/package.ps1
```

Produces versioned archives and SHA-256 checksums under `dist/`.

## Acceptance harness

```bash
./scripts/acceptance/v1-acceptance.sh
# or
./scripts/acceptance/v1-acceptance.ps1
```

## Known limitations

- Product `assess` orchestrates existing engines via offline fixtures for demos; live MCP discovery remains `discover`.
- PDF reports are out of scope for v1 (HTML primary).
- No new scale/perf subsystem — see performance baseline notes in Cycle 011 PROOF.
