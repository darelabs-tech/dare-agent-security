# Changelog

All notable changes to DARE Agent Security are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/); this
project has not yet reached `1.0.0`, so the public CLI/config/schema surface may
still change between minor versions during the pre-1.0 cycles.

## [Unreleased]

### Added

- `book/en` — mdBook user documentation site (installation, quickstart, commands,
  assessments, reports, privacy, CI, reference). Publishing pipeline via GitHub
  Pages (`.github/workflows/deploy-docs.yml`). `book/pt` scaffolded with the same
  navigation; content translation is tracked separately and not yet complete.
- `installers/install.sh` and `installers/install.ps1` — one-line installers for
  Linux/macOS and Windows. Both verify the release SHA-256 checksum and refuse to
  install on a missing or mismatched checksum (fail-closed).
- `.github/workflows/release.yml` — tag-triggered release pipeline building
  Linux (x86_64, aarch64), macOS (x86_64, aarch64), and Windows (x86_64)
  binaries, publishing `SHA256SUMS`, a CycloneDX SBOM, and GitHub Artifact
  Attestation for build provenance alongside the GitHub Release.
- `packaging/homebrew` and `packaging/winget` — local scaffolding for a Homebrew
  formula and a WinGet manifest. Not yet submitted to the public
  homebrew-core/winget-pkgs registries.

### Fixed

- `scripts/release/package.sh` no longer silently skips `LICENSE` when staging a
  release archive (previous line copied `README.md` a second time instead).
  `scripts/release/package.ps1` now includes `LICENSE` as well.

### Changed

- `scripts/release/package.sh` / `package.ps1` accept an optional platform target
  label so multi-platform release builds produce distinct archive names
  (`dare-agent-security-v{VERSION}-{target}.tar.gz`/`.zip`); local/dev usage with
  no argument is unchanged.

## Prior work (Cycles 001–011)

Summarized here for context; each cycle's detailed evidence lives under
`DARE/cycles/`. No dedicated release was tagged for these cycles.

- **Cycle 001** — protocol-neutral security evidence kernel (`dare-security-evidence`).
- **Cycle 002** — passive MCP discovery (`discover`).
- **Cycle 003** — COAZ authorization-integrity validation harness.
- **Cycle 004** — repository-local GitHub Action (`action.yml`) CI security gate.
- **Cycle 005** — synthetic MCP security lab and scenario corpus.
- **Cycle 006** — assessment profiles and coverage engine.
- **Cycle 007** — benchmark corpus methodology.
- **Cycle 008** — deterministic bounded agent attack-graph analysis.
- **Cycle 009** — ROE-gated, budgeted, offline-first adversarial validation.
- **Cycle 010** — immutable snapshots, incremental planning, fail-closed continuous validation.
- **Cycle 011** — productization: `init` / `assess` / `report` / `doctor` CLI and v1 config/artifact contract.

[Unreleased]: https://github.com/darelabs-tech/dare-agent-security/compare/main...HEAD
