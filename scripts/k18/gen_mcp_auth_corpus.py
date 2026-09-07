#!/usr/bin/env python3
"""Generate the MCP-AUTH-SECURITY corpus and its registry.

The corpus mirrors the lab table in `gen_mcp_auth_scenarios.py`: one entry per
lab that is actually evaluated. Generating both from the same source is what
keeps a vector from claiming a surface its invariant does not report under.

Every entry records a *behaviour*, never a verdict. Registry digests are
computed over the same canonical JSON the Rust loader hashes, so a hand-edited
vector fails verification instead of loading quietly.

`--check` verifies the committed files match, which is what CI runs.
"""

import argparse
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from gen_mcp_auth_scenarios import LABS  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "corpus" / "mcp-auth-security" / "v1"

SURFACE_DIR = {
    "PROTOCOL_BINDING": "protocol-binding",
    "RESOURCE_AUTHORIZATION": "resource-authorization",
    "TOKEN_BINDING": "token-binding",
    "FLOW_INTEGRITY": "flow-integrity",
    "SCOPE_AND_REGISTRATION": "scope-and-registration",
    "CREDENTIAL_AND_IDENTITY": "credential-and-identity",
}

# One sentence per vector saying what the surface actually is. Prose, not a
# verdict: it tells a reader why the vector exists, never what it should score.
NOTES = {
    "COMPLIANT": "a flow that stays inside every boundary it was granted",
    "UNSUPPORTED_PROTOCOL_REVISION": "a server offering a revision the modern authorization surface does not cover",
    "METHOD_HEADER_BODY_MISMATCH": "a gateway routes on transport metadata while the server executes the body",
    "NAME_HEADER_BODY_MISMATCH": "the routed operation name and the executed one diverge",
    "RESOURCE_METADATA_MISMATCH": "metadata describing one resource is used to authorize another",
    "AUTHORIZATION_SERVER_NOT_ADVERTISED": "a client selects an authorization server the resource never advertised",
    "AUTHORIZATION_RESPONSE_ISSUER_MIX_UP": "a well-formed response arrives from an issuer that was never selected",
    "TOKEN_AUDIENCE_MISMATCH": "a validly issued token is presented to a resource it was not minted for",
    "TOKEN_VALIDITY_EVIDENCE_MISSING": "a token is accepted with no recorded verification behind it",
    "PKCE_DOWNGRADED": "a public-client flow drops from S256 to a method that binds nothing",
    "REDIRECT_OR_STATE_SUBSTITUTED": "an authorization response is delivered somewhere the request did not name",
    "SCOPE_STEP_UP_DROPPED_SCOPE": "a step-up retry silently discards privilege the request already required",
    "UNTRUSTED_REGISTRATION_RELIED": "a client identifier is accepted because an untrusted document asserts it",
    "INBOUND_CREDENTIAL_FORWARDED": "the credential presented to the MCP server is reused against an upstream service",
    "SELF_REPORTED_METADATA_PROMOTED": "protocol self-description is treated as an authenticated principal",
    "FINAL_OPERATION_MUTATED_AFTER_PERMIT": "the operation changes after the permit and the permit is reused anyway",
    "MULTIPLE_INDEPENDENT_VIOLATIONS": "one flow crossing several boundaries at once, each independently observable",
    "NO_RELEVANT_OBSERVATION": "a run that never produced the evidence the invariant needs",
}

STANDARD = {
    "source": "MCP",
    "reference": "2026-07-28 authorization",
    "status": "NORMATIVE",
}


def canonical(payload):
    """The same canonical form the Rust loader digests."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def digest(payload):
    return "sha256:" + hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


def entry_for(lab):
    n, title, (surface, prop), invariant, behavior, _ = lab
    legitimate = behavior == "COMPLIANT"
    return {
        "schema_version": "1",
        "id": "mcp-auth-%03d-%s" % (n, behavior.lower().replace("_", "-")),
        "title": title,
        "class": "BENIGN_CONTROL" if legitimate else "MCP_AUTH_ATTACK",
        "surface": surface,
        "property": prop,
        "expected_invariant": invariant,
        "reference_behavior": behavior,
        "preconditions": ["mcp_current_protocol_present", "mcp_http_transport_present"],
        "surface_note": NOTES[behavior],
        "safety_class": "SYNTHETIC_NOOP",
        "standards": [STANDARD],
    }


def build():
    files = {}
    listed = []
    # Lab 22 asks for a retry count outside the approved bound. It exists to be
    # refused by the schema, so it never becomes a corpus vector: a vector the
    # loader cannot admit would make the corpus unloadable.
    for lab in LABS:
        if lab[0] == 22:
            continue
        entry = entry_for(lab)
        path = "%s/%s.json" % (SURFACE_DIR[entry["surface"]], entry["id"])
        files[path] = json.dumps(entry, indent=2, ensure_ascii=False) + "\n"
        listed.append({"id": entry["id"], "path": path, "digest": digest(entry)})

    registry = {
        "schema_version": "1",
        "corpus_id": "mcp-auth-security-v1",
        "version": "1.0.0",
        "title": "DARE Cycle 018 MCP 2026 authentication and authorization vectors",
        "entries": listed,
    }
    files["registry.json"] = json.dumps(registry, indent=2, ensure_ascii=False) + "\n"
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify without writing")
    args = parser.parse_args()

    files = build()

    if args.check:
        differences = []
        for name, text in sorted(files.items()):
            path = OUT / name
            if not path.exists():
                differences.append(f"missing {name}")
            elif path.read_text(encoding="utf-8") != text:
                differences.append(f"differs {name}")
        for path in sorted(OUT.rglob("*.json")):
            relative = path.relative_to(OUT).as_posix()
            # The adversarial parser fixtures live under this root but are not
            # corpus vectors: they exist to be refused, and the loader ignores
            # them entirely. Sweeping them here would report the corpus as out
            # of date every time a hostile case is added.
            if relative.startswith("adversarial-parser-fixtures/"):
                continue
            if relative not in files:
                differences.append(f"unexpected {relative}")
        if differences:
            print("mcp-auth-security corpus is out of date:", file=sys.stderr)
            for line in differences:
                print(f"  {line}", file=sys.stderr)
            return 1
        print(f"mcp-auth-security corpus is current ({len(files) - 1} vectors)")
        return 0

    for name, text in files.items():
        path = OUT / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {len(files) - 1} vectors under {OUT.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
