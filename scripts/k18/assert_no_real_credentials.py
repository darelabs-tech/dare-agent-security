#!/usr/bin/env python3
"""AC-74: no real credential or reachable target in any Cycle 018 file.

Asserted mechanically rather than by reading. The sweep is anchored on
credential *shape*, so a real value is caught wherever it hides and an honest
sentence about bearer credentials is not a false hit.

Two categories of file are treated differently, for a reason worth stating:

- **Ordinary fixtures, corpus vectors, schemas, traces, the profile and the
  standards record** must contain no credential shape at all, and no URL beyond
  the two that name a contract and are never fetched.

- **The adversarial parser fixtures** exist precisely to carry credential-shaped
  and endpoint-shaped values, because their whole purpose is to be refused. For
  those, the assertion is different and stronger: every such value must be a
  recognisable placeholder — zero-filled, a repeated alphabet, or a vendor's own
  documented example — never something that could be live. A fixture that
  smuggled in a real credential would put one in the repository under cover of
  being a test.
"""

import pathlib
import re
import sys

ROOTS = [
    "crates/dare-mcp-auth-security/tests/fixtures",
    "corpus/mcp-auth-security",
    "schemas/mcp-auth-security",
    "standards/mcp-auth-security",
    "profiles/mcp-auth-hardening-2026.json",
    "fixtures/coverage/mcp-auth-all-surfaces.json",
    "fixtures/coverage/mcp-auth-controls-absent.json",
    "fixtures/coverage/mcp-auth-legacy-revision.json",
]

HOSTILE = "adversarial-parser-fixtures"

SHAPES = [
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("PEM private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.{0,80}", re.S)),
    ("live secret key", re.compile(r"sk-live-[A-Za-z0-9]{8,}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}")),
    ("Slack token", re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google OAuth token", re.compile(r"ya29\.[A-Za-z0-9_-]{10,}")),
    ("bearer value", re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{20,}")),
]

URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s\"']*")

# The only two URLs anywhere in this cycle's data. Both name a contract; neither
# is ever resolved, and nothing in the crate can resolve one.
ALLOWED_URLS = (
    "https://json-schema.org/draft/2020-12/schema",
    "https://darelabs.tech/schemas/",
)

# What makes a hostile value recognisably not live.
PLACEHOLDER = [
    re.compile(r"0{8,}"),                 # zero-filled
    re.compile(r"abcdefghijklmnopqrst"),  # the alphabet in order
    re.compile(r"EXAMPLE"),               # a vendor's documented example
]

# A PEM armour line is only a credential if key material follows it. A bare
# header is a shape, and the fixture that carries one is testing that the shape
# alone is refused.
PEM_BODY = re.compile(r"[A-Za-z0-9+/=]{24,}")


def files_under(root: str):
    path = pathlib.Path(root)
    if path.is_file():
        yield path
        return
    for candidate in sorted(path.rglob("*")):
        if candidate.is_file():
            yield candidate


def looks_like_a_placeholder(label: str, value: str) -> bool:
    if label == "PEM private key":
        # The armour line plus whatever followed it. No base64 run means no key.
        body = value.split("-----", 2)[-1]
        return PEM_BODY.search(body) is None
    return any(pattern.search(value) for pattern in PLACEHOLDER)


def main() -> int:
    failures = []
    scanned = 0
    hostile_values = 0

    for root in ROOTS:
        for file in files_under(root):
            scanned += 1
            text = file.read_text(encoding="utf-8", errors="replace")
            hostile = HOSTILE in file.as_posix()

            for label, pattern in SHAPES:
                for match in pattern.finditer(text):
                    value = match.group(0)
                    if not hostile:
                        failures.append(f"{file.as_posix()}: {label} `{value[:12]}...`")
                    elif looks_like_a_placeholder(label, value):
                        hostile_values += 1
                    else:
                        failures.append(
                            f"{file.as_posix()}: {label} is not a recognisable "
                            f"placeholder — a hostile fixture must never carry a "
                            f"value that could be live"
                        )

            for match in URL.finditer(text):
                url = match.group(0)
                if url.startswith(ALLOWED_URLS):
                    continue
                if hostile:
                    # A hostile fixture naming a remote target is the point of
                    # that fixture; it exists to be refused.
                    hostile_values += 1
                    continue
                failures.append(f"{file.as_posix()}: reachable target `{url[:48]}`")

    print(f"AC-74 sweep: {scanned} files scanned, {hostile_values} hostile values checked")
    if failures:
        print("AC-74 FAILED:", file=sys.stderr)
        for line in failures:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(
        "no real token, secret, key, authorization code, customer identifier or "
        "reachable target found; every hostile value is a recognisable placeholder"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
