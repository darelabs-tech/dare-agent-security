#!/usr/bin/env python3
"""No real credential, key or live A2A/identity endpoint in Cycle 020 files.

Asserted mechanically rather than by reading, and the rule differs by file for a
reason worth stating.

**Shipping code** (`src/**`, outside `#[cfg(test)]`) must contain no credential
shape and no live identity-provider, key-set or model-API endpoint at all. This
is the strongest place to check: a `const` or `static` holding an endpoint is
where a fetch would start, and unlike a refusal list it has no legitimate reason
to exist.

**Tests and guard lists** must contain no credential shape, but *are* allowed to
name endpoints. They have to: a test that asserts a live issuer host never
reaches an artifact has to write the host down in order to look for it, and
`generators.rs` holds a list of exactly those hosts. Banning the strings there
would mean deleting the check that keeps them out.

**JSON artifacts** — the profile, the standards provenance record, and anything
a run writes under the output directory — must contain neither. They are the
files that leave the repository.

Two classes of string stay allowed everywhere, and getting this wrong in either
direction breaks the engine:

* Schema identifiers under `darelabs.tech` name a contract, and nothing fetches
  them.
* Reserved documentation hosts — `peer.example`, `issuer.example`,
  `callback.example` and the `*.example.com` family — are what an Agent Card
  fixture is *made of*. A sweep that refused them would refuse every fixture
  describing an A2A interface, and the fixtures would be deleted rather than the
  sweep.

Run from the repository root.
"""

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

SHIPPING_SOURCES = [
    "crates/dare-a2a-security/src",
    "crates/dare-agent-security-cli/src/a2a_security.rs",
]

TEST_SOURCES = [
    "crates/dare-a2a-security/tests",
    "crates/dare-coverage/tests/a2a_profile.rs",
    "crates/dare-coverage/tests/a2a_properties.rs",
]

JSON_ARTIFACTS = [
    "profiles/agentic-a2a-security-2026.json",
    "standards/a2a-security",
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
    re.compile(r"client_secret=[A-Za-z0-9._~+/-]{8,}"),
]

# Hosts this engine must never reach. Naming one in shipping code would be the
# first half of adding the capability.
#
# These are the places an A2A engine would be tempted to go: an issuer to get a
# token from, a key set to resolve a `jku` against, a registry to discover a
# peer in, and a model API to ask about one.
LIVE_ENDPOINTS = [
    "accounts.google.com",
    "oauth2.googleapis.com",
    "www.googleapis.com",
    "login.microsoftonline.com",
    "graph.microsoft.com",
    "token.actions.githubusercontent.com",
    "api.github.com",
    "github.com",
    "gitlab.com",
    "auth0.com",
    "okta.com",
    "api.openai.com",
    "api.anthropic.com",
    "huggingface.co",
    "registry.npmjs.org",
    "pypi.org",
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
    everything after the first `#[cfg(test)]` as test code — fails **open** on
    any file that puts a test module in the middle, and this crate has several:
    `lib.rs` carries tests inside its `limits` module above the crate-level
    ones, and `model.rs` exposes a `pub(crate) mod tests` used by other modules.

    Cycle 019 shipped the simpler rule and had to correct it. The corrected rule
    is carried here from the start rather than rediscovered.
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

    swept_shipping = 0
    for spec in SHIPPING_SOURCES:
        for path in files(spec, (".rs",)):
            swept_shipping += 1
            relative = path.relative_to(REPO)
            for number, line in shipping_lines(path):
                for hit in endpoint_hits(line):
                    failures.append(f"{relative}:{number}: shipping code names `{hit}`")
                if credential_hits(line):
                    failures.append(
                        f"{relative}:{number}: shipping code carries a credential shape"
                    )

    swept_tests = 0
    for spec in TEST_SOURCES:
        for path in files(spec, (".rs",)):
            swept_tests += 1
            relative = path.relative_to(REPO)
            if credential_hits(path.read_text(encoding="utf-8")):
                failures.append(f"{relative}: a test carries a credential shape")

    swept_json = 0
    for spec in JSON_ARTIFACTS:
        for path in files(spec, (".json",)):
            swept_json += 1
            relative = path.relative_to(REPO)
            text = path.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), start=1):
                for hit in endpoint_hits(line):
                    failures.append(f"{relative}:{number}: artifact names `{hit}`")
            if credential_hits(text):
                failures.append(f"{relative}: artifact carries a credential shape")

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
            if credential_hits(text):
                failures.append(f"{relative}: written artifact carries a credential shape")

    # A sweep that found no files would report success having checked nothing,
    # which is the failure mode this whole script exists to prevent one layer
    # down.
    if swept_shipping == 0 or swept_tests == 0 or swept_json == 0:
        print(
            "credential sweep failed: it swept "
            f"{swept_shipping} shipping file(s), {swept_tests} test file(s) and "
            f"{swept_json} artifact(s); a sweep that reads nothing proves nothing"
        )
        return 1

    if failures:
        print("credential sweep failed:")
        for failure in failures:
            print(f"  {failure}")
        return 1

    print(
        "no credential shape or live endpoint in Cycle 020 shipping code or artifacts "
        f"({swept_shipping} shipping file(s), {swept_tests} test file(s), "
        f"{swept_json} artifact(s))"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
