# Environment Variables

## Installer variables

These only apply to `installers/install.sh` / `install.ps1` — the CLI itself
does not read them.

| Variable | Effect | Default |
|---|---|---|
| `DARE_SECURITY_VERSION` | Pin a specific release tag (e.g. `v1.0.0`) instead of resolving the latest. | latest release |
| `DARE_SECURITY_INSTALL_DIR` | Where the binary is installed. | `~/.local/bin` (Unix), `%LOCALAPPDATA%\dare-security\bin` (Windows) |
| `DARE_SECURITY_REPO` | GitHub `owner/repo` to resolve releases from. | `darelabs-tech/dare-agent-security` |

## No secret-bearing environment variables

There are no `DARE_SECURITY_TOKEN`-style variables and no supported way to
pass credentials via the environment for the CLI itself — this mirrors the
"no `--token`/`--password`/`--credential` flags" rule from
[Redaction](../privacy/redaction.md). Command-line flags remain the
documented interface for everything except the three installer variables
above.
