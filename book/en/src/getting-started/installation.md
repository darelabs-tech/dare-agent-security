# Installation

You do **not** need to install Rust to use DARE Agent Security. Pick one of
the methods below, in order of preference.

## 1. Official installer (recommended)

### Linux / macOS

```bash
curl -fsSL https://darelabs.tech/security/install | sh
```

### Windows (PowerShell)

```powershell
irm https://darelabs.tech/security/install.ps1 | iex
```

Both installers:

1. detect your OS and architecture;
2. resolve the latest stable release (or a version pinned via
   `DARE_SECURITY_VERSION`);
3. download the matching release archive and its `SHA256SUMS` entry;
4. **verify the checksum and abort the install on any mismatch or missing
   checksum** — there is no "warn and continue" path for a security tool;
5. install the binary (default: `~/.local/bin` on Unix,
   `%LOCALAPPDATA%\dare-security\bin` on Windows) and validate it by running
   `--version`.

Source: [`installers/install.sh`](https://github.com/darelabs-tech/dare-agent-security/blob/main/installers/install.sh),
[`installers/install.ps1`](https://github.com/darelabs-tech/dare-agent-security/blob/main/installers/install.ps1).

## 2. Manual GitHub Release download

Every release publishes, per supported platform: the archive (`.tar.gz` on
Linux/macOS, `.zip` on Windows), a `SHA256SUMS` file, and a CycloneDX SBOM.
Verify the checksum yourself before running the binary:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

## 3. Cargo (fallback for developers)

If published to crates.io:

```bash
cargo install dare-agent-security --locked
```

## 4. Build from source

```bash
git clone https://github.com/darelabs-tech/dare-agent-security.git
cd dare-agent-security
cargo build -p dare-agent-security --release
```

MSRV: **1.88**. This is the path for contributors, not the recommended path
for end users.

## Verify the installation

Every install method ends with:

```bash
dare-agent-security --version
dare-agent-security doctor
```

Expected:

```text
dare-agent-security 1.0.0
doctor: PASS
```

## Supported platforms (v1 target matrix)

| Platform | Status |
|---|---|
| Linux x86_64 | Officially supported |
| Linux aarch64 | Officially supported |
| macOS x86_64 | Officially supported |
| macOS aarch64 | Officially supported |
| Windows x86_64 | Officially supported |

A platform is only announced as officially supported once it is covered by
acceptance testing (see the project's Product Validation Program).

## Uninstall

The installer only manages the binary. Removing it does **not** delete any
of the following — clean those up explicitly if you want to remove all local
data:

| What | Where |
|---|---|
| Binary | `~/.local/bin/dare-agent-security` (or your `DARE_SECURITY_INSTALL_DIR`) |
| Config | `dare-security.yaml` / `.dare-security/config.yaml` in each project |
| Evidence & reports | `.dare-security/runs/` in each assessed project |

## Upgrade

Re-run the installer — it always resolves the latest release, replaces the
binary in place, and preserves your project config. Run `dare-agent-security
doctor` afterwards to confirm the new binary and config are compatible.
