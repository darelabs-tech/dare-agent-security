# Packaging scaffolds

This directory holds local templates for third-party package managers. They are
**not** yet published to the real Homebrew or WinGet registries — they exist so
the manifests can be prepared, reviewed, and kept in sync with each GitHub
Release ahead of an eventual submission.

The supported install path for v1 remains the one documented in
[`docs/product/packaging-install.md`](../docs/product/packaging-install.md):
the official installer scripts (`installers/install.sh` / `installers/install.ps1`),
falling back to a manual GitHub Release download, `cargo install`, or building
from source.

## `homebrew/`

`dare-agent-security.rb` is a formula template pointing at the macOS release
tarballs. The `sha256` values are placeholders — fill them in from the
release's `SHA256SUMS` file before tapping/testing locally:

```bash
brew install --build-from-source ./packaging/homebrew/dare-agent-security.rb
```

Publishing to `homebrew-core` (or a dedicated `darelabs-tech/homebrew-tap`) is
future work, tracked once the installer has been validated end-to-end.

## `winget/`

The three manifest files under `winget/manifests/darelabs-tech.DareAgentSecurity/`
follow the WinGet community repository layout (version / installer / locale).
The `InstallerSha256` values are placeholders — fill them in from the release's
`SHA256SUMS` file. Validate locally with:

```powershell
winget validate --manifest packaging/winget/manifests/darelabs-tech.DareAgentSecurity
```

Submitting to `microsoft/winget-pkgs` is future work.
