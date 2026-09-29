#!/usr/bin/env python3
"""No real credential, key or live endpoint in Cycle 025 files.

Derived from `scripts/k24/assert_no_real_credentials.py` with Cycle 025 file
lists; the rules and the test-module skipping are unchanged, with one addition.

Cycle 025 opens no socket and emits no telemetry (RS-08):
`dare-runtime-telemetry` reads OTLP/JSON exports and an optional runtime policy
and writes four files. The sweep matters twice over here, because trace exports
are exactly where real systems leak credentials, and the OTEL-LAB fixtures and
refusal corpus plant credential-shaped values on purpose.

**The addition: synthetic markers.** Every planted credential-shaped value in
this cycle carries the product's synthetic marker `DARE-SYNTHETIC-CANARY-`
(the first entry of the output sweep's markers). A match whose text contains
that marker is synthetic by construction and is removed before the shape
patterns run; anything else of real length still fails. No other exemption
exists.

**Shipping code** (`src/**`, outside `#[cfg(test)]`) must contain no credential
shape and no live identity-provider, key-set, model-API or telemetry-collector
endpoint (a collector address in shipping code would be the first half of
emitting telemetry).

**Tests** and **JSON artifacts** (the runtime-telemetry schemas, the pinned
semantic-convention mapping, the recorded OTEL-LAB copies, the Cycle 023 `rt`
bundle, and anything a run writes under `.dare-agent-security/`) must contain
no credential shape, and artifacts no live endpoint.

Run from the repository root.
"""

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

SHIPPING_SOURCES = [
    "crates/dare-runtime-telemetry/src",
    "crates/dare-agent-security-cli/src/runtime_telemetry.rs",
    "crates/dare-attack-path/src/project/runtime_telemetry.rs",
]

TEST_SOURCES = [
    "crates/dare-runtime-telemetry/tests",
    "crates/dare-agent-security-cli/tests/runtime_telemetry_cli.rs",
    "crates/dare-agent-security-cli/tests/runtime_telemetry_refusals.rs",
    "crates/dare-coverage/tests/runtime_telemetry_properties.rs",
    "crates/dare-coverage/tests/runtime_telemetry_profile.rs",
]

JSON_ARTIFACTS = [
    "schemas/runtime-telemetry/v1",
    "standards/runtime-telemetry/2026",
    "profiles/runtime-telemetry-baseline-2026.json",
    "crates/dare-runtime-telemetry/tests/fixtures/otel-lab",
    "crates/dare-attack-path/tests/fixtures/bundles/rt",
]

# The product's synthetic marker; a value carrying it is planted, not issued.
SYNTHETIC = re.compile(r"DARE-SYNTHETIC-CANARY-[A-Za-z0-9-]*")

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
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
    "api.cohere.ai",
    "localhost:11434",
    "huggingface.co",
    "registry.npmjs.org",
    "pypi.org",
    # Telemetry collectors and vendor intakes (RS-08).
    ":4317",
    ":4318",
    "otel-collector",
    "otlp.nr-data.net",
    "api.honeycomb.io",
    "ingest.lightstep.com",
    "otlp-gateway",
    "datadoghq.com",
]

# The pinned upstream sources of the semantic-convention mapping are cited in
# its provenance record; they are references, never fetched.
ALLOWED_URL_SUBSTRINGS = [
    "darelabs.tech/schemas/",
    '"https://github.com/open-telemetry/semantic-conventions"',
    '"https://github.com/open-telemetry/semantic-conventions-genai"',
]


def files(spec: str, suffixes: tuple[str, ...]) -> list[pathlib.Path]:
    path = REPO / spec
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []
    return sorted(p for p in path.rglob("*") if p.is_file() and p.suffix in suffixes)


def credential_hits(text: str) -> list[str]:
    text = SYNTHETIC.sub("<synthetic>", text)
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
        "no credential shape or live endpoint in Cycle 025 shipping code or artifacts "
        f"({swept_shipping} shipping file(s), {swept_tests} test file(s), "
        f"{swept_json} artifact(s))"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
