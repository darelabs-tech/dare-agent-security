# Packaging and install (Product v1)

## End-user install (recommended)

```bash
# Linux/macOS
curl -fsSL https://darelabs.tech/security/install | sh

# Windows PowerShell
irm https://darelabs.tech/security/install.ps1 | iex
```

Both installers resolve the latest GitHub Release (or a version pinned via
`DARE_SECURITY_VERSION`), download the matching platform archive, **verify
the SHA-256 checksum and abort on any mismatch or missing checksum
(fail-closed)**, then install and validate with `--version`. Source:
[`installers/install.sh`](../../installers/install.sh),
[`installers/install.ps1`](../../installers/install.ps1). Full walkthrough:
the [Installation](https://darelabs-tech.github.io/dare-agent-security/en/getting-started/installation.html)
page of the docs site (`book/en`).

Fallbacks, in order: manual GitHub Release download + checksum verification,
`cargo install dare-agent-security --locked` (once published to crates.io),
build from source (below). Build-from-source is the contributor path, not
the recommended end-user path.

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
# Unix, optionally with a platform target label (e.g. linux-x86_64)
./scripts/release/package.sh [target-label]

# Windows PowerShell
./scripts/release/package.ps1 [-Target <platform-label>]
```

Produces versioned archives and SHA-256 checksums under `dist/`. The
tag-triggered `.github/workflows/release.yml` pipeline runs this per
platform (Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64),
aggregates one `SHA256SUMS`, generates a CycloneDX SBOM via `cargo
cyclonedx`, attests build provenance via `actions/attest-build-provenance`
(GitHub Artifact Attestation), and publishes the GitHub Release.

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
