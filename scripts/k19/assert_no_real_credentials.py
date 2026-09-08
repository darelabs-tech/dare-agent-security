#!/usr/bin/env python3
"""AC-83: no real credential, key or live registry endpoint in Cycle 019 files.

Asserted mechanically rather than by reading, and the rule differs by file for a
reason worth stating.

**Shipping code** (`src/**`, outside `#[cfg(test)]`) must contain no credential
shape and no live registry, model-hub, container-registry or transparency-log
endpoint at all. This is the strongest place to check: a `const` or `static`
holding an endpoint is where a fetch would start, and unlike a refusal list it
has no legitimate reason to exist.

**Tests and guard lists** must contain no credential shape, but *are* allowed to
name endpoints. They have to: a test that asserts a live registry host never
reaches an artifact has to write the host down in order to look for it, and
`generators.rs` holds a list of exactly those hosts. Banning the strings there
would mean deleting the check that keeps them out.

**JSON artifacts** — the profile, the standards provenance record, and anything
a run writes under the output directory — must contain neither. They are the
files that leave the repository.

The schema identifiers under `darelabs.tech` are allowed everywhere: they name a
contract and nothing fetches them.
"""

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

SHIPPING_SOURCES = [
    "crates/dare-supply-chain-security/src",
    "crates/dare-agent-security-cli/src/supply_chain_security.rs",
]

TEST_SOURCES = [
    "crates/dare-supply-chain-security/tests",
    "crates/dare-coverage/tests/supply_chain_profile.rs",
    "crates/dare-coverage/tests/supply_chain_properties.rs",
]

JSON_ARTIFACTS = [
    "profiles/agentic-supply-chain-security-2026.json",
    "standards/supply-chain-security",
]

# Credential shapes real providers issue. Anchored on shape so an honest
# sentence about bearer tokens stays writable while a live value is caught.
CREDENTIAL_PATTERNS = [
    re.compile(r"sk-live-[A-Za-z0-9]{8,}"),
    re.compile(r"sk_live_[A-Za-z0-9]{8,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}"),
]

# Hosts this engine must never reach. Naming one in shipping code would be the
# first half of adding the capability.
LIVE_ENDPOINTS = [
    "registry.npmjs.org",
    "pypi.org",
    "index.crates.io",
    "repo.maven.apache.org",
    "proxy.golang.org",
    "huggingface.co",
    "ghcr.io",
    "docker.io",
    "index.docker.io",
    "github.com",
    "gitlab.com",
    "rekor.sigstore.dev",
    "fulcio.sigstore.dev",
    "oauth2.sigstore.dev",
    "nvd.nist.gov",
    "osv.dev",
]

ALLOWED_URL_SUBSTRINGS = ["darelabs.tech/schemas/"]


def files(spec: str, suffixes: tuple[str, ...]) -> list[pathlib.Path]:
    path = REPO / spec
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []
    return sorted(p for p in path.rglob("*") if p.is_file() and p.suffix in suffixes)


def credential_hits(text: str) -> list[str]:
    hits = []
    for pattern in CREDENTIAL_PATTERNS:
        hits.extend(match.group(0) for match in pattern.finditer(text))
    return hits


def endpoint_hits(line: str) -> list[str]:
    if any(allowed in line for allowed in ALLOWED_URL_SUBSTRINGS):
        return []
    return [host for host in LIVE_ENDPOINTS if host in line]


def shipping_lines(path: pathlib.Path) -> list[tuple[int, str]]:
    """Lines outside every `#[cfg(test)]` module.

    Each test module is skipped by tracking braces from its opening line to its
    closing one, and sweeping resumes afterwards. The simpler rule — treat
    everything after the first `#[cfg(test)]` as test code — would fail open on
    any file that puts a test module in the middle, and `lib.rs` already does:
    its `limits` module carries its own tests above the crate-level ones.
    """
    kept: list[tuple[int, str]] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    depth = 0
    in_test = False

    for number, line in enumerate(lines, start=1):
        if not in_test and line.strip().startswith("#[cfg(test)]"):
            in_test = True
            depth = 0
            continue
        if in_test:
            depth += line.count("{") - line.count("}")
            # The module has closed once the braces balance, which cannot
            # happen before the opening one is seen.
            if depth <= 0 and "}" in line:
                in_test = False
            continue
        kept.append((number, line))

    return kept


def main() -> int:
    failures: list[str] = []

    for spec in SHIPPING_SOURCES:
        for path in files(spec, (".rs",)):
            relative = path.relative_to(REPO)
            for number, line in shipping_lines(path):
                for hit in endpoint_hits(line):
                    failures.append(f"{relative}:{number}: shipping code names `{hit}`")
                for hit in credential_hits(line):
                    failures.append(
                        f"{relative}:{number}: shipping code carries a credential shape"
                    )
                    del hit

    for spec in TEST_SOURCES:
        for path in files(spec, (".rs",)):
            relative = path.relative_to(REPO)
            for hit in credential_hits(path.read_text(encoding="utf-8")):
                failures.append(f"{relative}: a test carries a credential shape")
                del hit

    for spec in JSON_ARTIFACTS:
        for path in files(spec, (".json",)):
            relative = path.relative_to(REPO)
            text = path.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), start=1):
                for hit in endpoint_hits(line):
                    failures.append(f"{relative}:{number}: artifact names `{hit}`")
            for hit in credential_hits(text):
                failures.append(f"{relative}: artifact carries a credential shape")
                del hit

    output_dir = REPO / ".dare-agent-security"
    if output_dir.is_dir():
        for path in sorted(output_dir.rglob("*")):
            if not path.is_file() or path.suffix not in (".json", ".md"):
                continue
            relative = path.relative_to(REPO)
            text = path.read_text(encoding="utf-8", errors="replace")
            for number, line in enumerate(text.splitlines(), start=1):
                for hit in endpoint_hits(line):
                    failures.append(f"{relative}:{number}: written artifact names `{hit}`")
            for hit in credential_hits(text):
                failures.append(f"{relative}: written artifact carries a credential shape")
                del hit

    if failures:
        print("AC-83 failed:")
        for failure in failures:
            print(f"  {failure}")
        return 1

    print("AC-83: no credential shape or live endpoint in Cycle 019 shipping code or artifacts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
