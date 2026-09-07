#!/usr/bin/env python3
"""Generate the Cycle 018 MCP auth-security JSON schemas.

The schemas are generated rather than hand-written so the closed enums cannot
drift from each other: an invariant added in one schema and forgotten in another
would let a corpus entry name something a scenario could never carry.

`--check` verifies the committed files match, which is what CI runs.
"""

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "schemas" / "mcp-auth-security" / "v1"
BASE_ID = "https://darelabs.tech/schemas/mcp-auth-security/v1"

INVARIANTS = [
    "MCP_PROTOCOL_REVISION_PRESERVED",
    "MCP_METHOD_HEADER_BODY_BINDING_PRESERVED",
    "MCP_NAME_HEADER_BODY_BINDING_PRESERVED",
    "PROTECTED_RESOURCE_METADATA_BOUND_TO_RESOURCE",
    "AUTHORIZATION_SERVER_ISSUER_BOUNDARY_PRESERVED",
    "AUTHORIZATION_RESPONSE_ISSUER_PRESERVED",
    "TOKEN_RESOURCE_AUDIENCE_BOUNDARY_PRESERVED",
    "TOKEN_VALIDITY_EVIDENCE_PRESENT",
    "PKCE_BINDING_PRESERVED",
    "REDIRECT_STATE_BINDING_PRESERVED",
    "SCOPE_STEP_UP_DOES_NOT_DROP_REQUIRED_SCOPE",
    "CLIENT_REGISTRATION_METADATA_TRUST_PRESERVED",
    "INBOUND_CREDENTIAL_NOT_REUSED_AS_UPSTREAM_AUTHORITY",
    "FINAL_OPERATION_AUTHORIZATION_BINDING_PRESERVED",
]

PROPERTIES = [
    "MCP.AUTH.PROTOCOL_BINDING",
    "MCP.AUTH.PROTECTED_RESOURCE_METADATA",
    "MCP.AUTH.AUTHORIZATION_SERVER_BINDING",
    "MCP.AUTH.TOKEN_AUDIENCE_RESOURCE_BINDING",
    "MCP.AUTH.PKCE_REDIRECT_STATE_INTEGRITY",
    "MCP.AUTH.SCOPE_STEP_UP_INTEGRITY",
    "MCP.AUTH.CLIENT_REGISTRATION_TRUST",
    "MCP.AUTH.CREDENTIAL_SEPARATION",
    "MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY",
    "MCP.AUTH.FINAL_OPERATION_BINDING",
]

SURFACES = [
    "PROTOCOL_BINDING",
    "RESOURCE_AUTHORIZATION",
    "TOKEN_BINDING",
    "FLOW_INTEGRITY",
    "SCOPE_AND_REGISTRATION",
    "CREDENTIAL_AND_IDENTITY",
]

BEHAVIORS = [
    "COMPLIANT",
    "UNSUPPORTED_PROTOCOL_REVISION",
    "METHOD_HEADER_BODY_MISMATCH",
    "NAME_HEADER_BODY_MISMATCH",
    "RESOURCE_METADATA_MISMATCH",
    "AUTHORIZATION_SERVER_NOT_ADVERTISED",
    "AUTHORIZATION_RESPONSE_ISSUER_MIX_UP",
    "TOKEN_AUDIENCE_MISMATCH",
    "TOKEN_VALIDITY_EVIDENCE_MISSING",
    "PKCE_DOWNGRADED",
    "REDIRECT_OR_STATE_SUBSTITUTED",
    "SCOPE_STEP_UP_DROPPED_SCOPE",
    "UNTRUSTED_REGISTRATION_RELIED",
    "INBOUND_CREDENTIAL_FORWARDED",
    "SELF_REPORTED_METADATA_PROMOTED",
    "FINAL_OPERATION_MUTATED_AFTER_PERMIT",
    "MULTIPLE_INDEPENDENT_VIOLATIONS",
    "NO_RELEVANT_OBSERVATION",
    "HARNESS_FAILURE",
]

TRUST_CLASSES = ["SELF_REPORTED", "DECLARED", "AUTHENTICATED"]
REGISTRATION_TRUST = [
    "PRE_REGISTERED",
    "CLIENT_METADATA_DOCUMENT",
    "DYNAMIC_REGISTRATION_LEGACY",
    "UNTRUSTED",
]
VALIDITY = ["VERIFIED", "REJECTED", "EXPIRED", "UNKNOWN"]
CHALLENGE_METHODS = ["S256", "PLAIN", "NONE"]
CREDENTIAL_CLASSES = ["INBOUND_MCP", "UPSTREAM_SERVICE", "EXCHANGED_DELEGATED"]
PRINCIPAL_KINDS = ["HUMAN", "AGENT", "WORKLOAD", "SERVICE"]
CORPUS_CLASSES = ["MCP_AUTH_ATTACK", "BENIGN_CONTROL"]

# A synthetic identity, never an address. The negative lookahead is what makes
# the offline guarantee structural rather than a matter of discipline: a fixture
# cannot express a URL at all.
SYNTHETIC_URI = {
    "type": "string",
    "minLength": 1,
    "maxLength": 256,
    "pattern": r"^(?!.*(://|^//))[A-Za-z0-9._:@+-]+$",
}

DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
IDENTIFIER = {"type": "string", "minLength": 1, "maxLength": 256}
SCOPE_LIST = {"type": "array", "maxItems": 32, "items": IDENTIFIER}


def obj(properties, required=(), additional=False):
    schema = {
        "type": "object",
        "additionalProperties": additional,
        "properties": properties,
    }
    if required:
        schema["required"] = list(required)
    return schema


def standards():
    return {
        "type": "array",
        "maxItems": 8,
        "items": obj(
            {
                "source": {"type": "string"},
                "reference": {"type": "string"},
                "status": {
                    "type": "string",
                    "enum": ["NORMATIVE", "DRAFT", "OPEN_PROPOSAL", "FUTURE", "INFORMATIVE"],
                },
            },
            required=["source", "reference", "status"],
        ),
    }


def scenario_schema():
    request = obj(
        {
            "request_id": IDENTIFIER,
            "protocol": obj(
                {
                    "declared_revision": IDENTIFIER,
                    "http_transport": {"type": "boolean"},
                },
                required=["declared_revision"],
            ),
            "headers": obj({"method": IDENTIFIER, "name": IDENTIFIER}),
            "operation": obj(
                {"method": IDENTIFIER, "name": IDENTIFIER}, required=["method"]
            ),
        },
        required=["request_id", "protocol", "operation"],
    )

    prm = obj(
        {
            "resource": SYNTHETIC_URI,
            "authorization_servers": {
                "type": "array",
                "maxItems": 8,
                "items": SYNTHETIC_URI,
            },
            "scopes_supported": SCOPE_LIST,
            "trust": {"type": "string", "enum": TRUST_CLASSES},
        },
        required=["resource", "trust"],
    )

    as_metadata = obj(
        {
            "issuer": SYNTHETIC_URI,
            "authorization_endpoint": SYNTHETIC_URI,
            "token_endpoint": SYNTHETIC_URI,
            "code_challenge_methods_supported": {
                "type": "array",
                "maxItems": 4,
                "items": {"type": "string", "enum": CHALLENGE_METHODS},
            },
            "trust": {"type": "string", "enum": TRUST_CLASSES},
        },
        required=["issuer", "trust"],
    )

    token_claims = obj(
        {
            "token_id": IDENTIFIER,
            "issuer": SYNTHETIC_URI,
            "subject": IDENTIFIER,
            "audience": {"type": "array", "maxItems": 16, "items": SYNTHETIC_URI},
            "resources": {"type": "array", "maxItems": 16, "items": SYNTHETIC_URI},
            "scopes": SCOPE_LIST,
            "validity": {"type": "string", "enum": VALIDITY},
        },
        required=["token_id", "issuer", "validity"],
    )

    operation = obj({"method": IDENTIFIER, "name": IDENTIFIER}, required=["method"])

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{BASE_ID}/scenario.schema.json",
        "title": "DARE Cycle 018 MCP auth-security scenario",
        **obj(
            {
                "schema_version": {"const": "1"},
                "id": IDENTIFIER,
                "title": {"type": "string", "minLength": 1},
                "class": {"type": "string", "enum": SURFACES},
                "property": {"type": "string", "enum": PROPERTIES},
                "objective": obj(
                    {
                        "id": IDENTIFIER,
                        "description": {"type": "string"},
                        "protected_canaries": {
                            "type": "array",
                            "maxItems": 8,
                            "items": IDENTIFIER,
                        },
                    },
                    required=["id", "description"],
                ),
                "requests": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 8,
                    "items": request,
                },
                "protected_resource": obj(
                    {
                        "expected_resource": SYNTHETIC_URI,
                        "metadata": prm,
                        "authorization_servers": {
                            "type": "array",
                            "maxItems": 8,
                            "items": as_metadata,
                        },
                        "selected_authorization_server": SYNTHETIC_URI,
                    },
                    required=["expected_resource"],
                ),
                "authorization_flow": obj(
                    {
                        "request": obj(
                            {
                                "request_id": IDENTIFIER,
                                "selected_issuer": SYNTHETIC_URI,
                                "resource_indicator": SYNTHETIC_URI,
                                "requested_scopes": SCOPE_LIST,
                                "state": IDENTIFIER,
                                "redirect_uri": SYNTHETIC_URI,
                            },
                            required=["request_id", "selected_issuer"],
                        ),
                        "response": obj(
                            {
                                "request_id": IDENTIFIER,
                                "response_issuer": SYNTHETIC_URI,
                                "state": IDENTIFIER,
                                "redirect_uri": SYNTHETIC_URI,
                                "accepted_by_client": {"type": "boolean"},
                            },
                            required=["request_id"],
                        ),
                    }
                ),
                "tokens": obj(
                    {
                        "presented": token_claims,
                        "target_resource": SYNTHETIC_URI,
                        "accepted_by_resource": {"type": "boolean"},
                    }
                ),
                "flow": obj(
                    {
                        "pkce": obj(
                            {
                                "s256_required": {"type": "boolean"},
                                "method": {"type": "string", "enum": CHALLENGE_METHODS},
                                "challenge_digest": DIGEST,
                                "verifier_digest": DIGEST,
                            },
                            required=["method"],
                        ),
                        "redirect": obj(
                            {
                                "registered": {
                                    "type": "array",
                                    "maxItems": 16,
                                    "items": SYNTHETIC_URI,
                                },
                                "requested": SYNTHETIC_URI,
                                "delivered": SYNTHETIC_URI,
                            }
                        ),
                    }
                ),
                "scope": obj(
                    {
                        "initial_required": SCOPE_LIST,
                        "challenge_required": SCOPE_LIST,
                        "retried": SCOPE_LIST,
                        "granted": SCOPE_LIST,
                        "retry_count": {"type": "integer", "minimum": 0, "maximum": 2},
                        "challenge_observed": {"type": "boolean"},
                    }
                ),
                "registration": obj(
                    {
                        "client_id": IDENTIFIER,
                        "trust_class": {"type": "string", "enum": REGISTRATION_TRUST},
                        "redirect_uris": {
                            "type": "array",
                            "maxItems": 16,
                            "items": SYNTHETIC_URI,
                        },
                        "relied_upon": {"type": "boolean"},
                    },
                    required=["client_id", "trust_class"],
                ),
                "credential_flow": obj(
                    {
                        "inbound": obj(
                            {
                                "credential_id": IDENTIFIER,
                                "class": {"type": "string", "enum": CREDENTIAL_CLASSES},
                                "material_digest": DIGEST,
                            },
                            required=["credential_id", "class"],
                        ),
                        "upstream": obj(
                            {
                                "credential_id": IDENTIFIER,
                                "class": {"type": "string", "enum": CREDENTIAL_CLASSES},
                                "material_digest": DIGEST,
                            },
                            required=["credential_id", "class"],
                        ),
                        "exchange_recorded": {"type": "boolean"},
                        "exchange_permitted": {"type": "boolean"},
                    }
                ),
                "identity_metadata": obj(
                    {
                        "client_info": obj(
                            {
                                "name": IDENTIFIER,
                                "version": IDENTIFIER,
                                "title": IDENTIFIER,
                            },
                            required=["name"],
                        ),
                        "server_info": obj(
                            {
                                "name": IDENTIFIER,
                                "version": IDENTIFIER,
                                "title": IDENTIFIER,
                            },
                            required=["name"],
                        ),
                        "acting_principal": obj(
                            {
                                "principal_id": IDENTIFIER,
                                "kind": {"type": "string", "enum": PRINCIPAL_KINDS},
                                "tenant_id": IDENTIFIER,
                                "trust": {"type": "string", "enum": TRUST_CLASSES},
                            },
                            required=["principal_id", "kind", "trust"],
                        ),
                        "principal_derived_from_self_report": {"type": "boolean"},
                    }
                ),
                "final_operation": obj(
                    {
                        "authorized_operation": operation,
                        "performed_operation": operation,
                        "authorized_resource": SYNTHETIC_URI,
                        "performed_resource": SYNTHETIC_URI,
                        "reevaluated_after_change": {"type": "boolean"},
                        "refused_after_change": {"type": "boolean"},
                    }
                ),
                "vector": obj(
                    {"corpus_id": IDENTIFIER, "corpus_digest": DIGEST},
                    required=["corpus_id"],
                ),
                "invariant": obj(
                    {"type": {"type": "string", "enum": INVARIANTS}}, required=["type"]
                ),
                "trials": obj(
                    {
                        "count": {"type": "integer", "minimum": 1, "maximum": 10},
                        "stop_on_first_fail": {"type": "boolean"},
                    },
                    required=["count"],
                ),
                "safety": obj(
                    {
                        "local_only": {"const": True},
                        "max_requests_per_trial": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 8,
                        },
                    },
                    required=["local_only"],
                ),
                "lab": obj(
                    {"reference_behavior": {"type": "string", "enum": BEHAVIORS}},
                    required=["reference_behavior"],
                ),
                "standards": standards(),
            },
            required=[
                "schema_version",
                "id",
                "title",
                "class",
                "property",
                "objective",
                "requests",
                "protected_resource",
                "invariant",
                "trials",
                "safety",
            ],
        ),
    }


def trace_schema():
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{BASE_ID}/trace.schema.json",
        "title": "DARE Cycle 018 MCP auth-security replay trace",
        **obj(
            {
                "schema_version": {"const": "1"},
                "trace_id": IDENTIFIER,
                "scenario_id": IDENTIFIER,
                # A trace can only ever be replayed. There is no mode in which
                # a recording becomes a live run.
                "mode": {"const": "REPLAY"},
                # And it can never claim to be production evidence.
                "synthetic": {"const": True},
                "description": {"type": "string"},
                "trials": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 10,
                    "items": obj(
                        {
                            "observed_requests": {
                                "type": "array",
                                "maxItems": 8,
                                "items": obj(
                                    {
                                        "request_id": IDENTIFIER,
                                        "protocol": obj(
                                            {
                                                "declared_revision": IDENTIFIER,
                                                "http_transport": {"type": "boolean"},
                                            },
                                            required=["declared_revision"],
                                        ),
                                        "headers": obj(
                                            {"method": IDENTIFIER, "name": IDENTIFIER}
                                        ),
                                        "operation": obj(
                                            {"method": IDENTIFIER, "name": IDENTIFIER},
                                            required=["method"],
                                        ),
                                    },
                                    required=["request_id", "protocol", "operation"],
                                ),
                            },
                            "harness_error": obj(
                                {
                                    "kind": {
                                        "type": "string",
                                        "enum": [
                                            "ADAPTER_FAILURE",
                                            "STAGING_FAILURE",
                                            "KILL_SWITCH_TRIGGERED",
                                            "BUDGET_EXHAUSTED",
                                        ],
                                    },
                                    "detail": {"type": "string"},
                                },
                                required=["kind", "detail"],
                            ),
                        }
                    ),
                },
            },
            required=["schema_version", "trace_id", "scenario_id", "mode", "synthetic", "trials"],
        ),
    }


def corpus_entry_schema():
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{BASE_ID}/corpus-entry.schema.json",
        "title": "DARE Cycle 018 MCP auth-security corpus entry",
        **obj(
            {
                "schema_version": {"const": "1"},
                "id": IDENTIFIER,
                "title": {"type": "string", "minLength": 1},
                "class": {"type": "string", "enum": CORPUS_CLASSES},
                "surface": {"type": "string", "enum": SURFACES},
                "property": {"type": "string", "enum": PROPERTIES},
                "expected_invariant": {"type": "string", "enum": INVARIANTS},
                "reference_behavior": {"type": "string", "enum": BEHAVIORS},
                "preconditions": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 8,
                    "items": IDENTIFIER,
                },
                "surface_note": {"type": "string", "minLength": 1},
                "safety_class": {"const": "SYNTHETIC_NOOP"},
                "standards": standards(),
            },
            required=[
                "schema_version",
                "id",
                "title",
                "class",
                "surface",
                "property",
                "expected_invariant",
                "reference_behavior",
                "preconditions",
                "surface_note",
                "safety_class",
                "standards",
            ],
        ),
    }


def corpus_registry_schema():
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{BASE_ID}/corpus-registry.schema.json",
        "title": "DARE Cycle 018 MCP auth-security corpus registry",
        **obj(
            {
                "schema_version": {"const": "1"},
                "corpus_id": IDENTIFIER,
                "version": IDENTIFIER,
                "title": {"type": "string"},
                "entries": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 64,
                    "items": obj(
                        {
                            "id": IDENTIFIER,
                            # Relative, root-confined, and never a URL.
                            "path": {
                                "type": "string",
                                "pattern": r"^(?!.*(\.\.|://|^/))[A-Za-z0-9._/-]+\.json$",
                            },
                            "digest": DIGEST,
                        },
                        required=["id", "path"],
                    ),
                },
            },
            required=["schema_version", "corpus_id", "version", "entries"],
        ),
    }


def build():
    return {
        "scenario.schema.json": scenario_schema(),
        "trace.schema.json": trace_schema(),
        "corpus-entry.schema.json": corpus_entry_schema(),
        "corpus-registry.schema.json": corpus_registry_schema(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify without writing")
    args = parser.parse_args()

    files = {
        name: json.dumps(schema, indent=2, ensure_ascii=False) + "\n"
        for name, schema in build().items()
    }

    if args.check:
        differences = []
        for name, text in sorted(files.items()):
            path = OUT / name
            if not path.exists():
                differences.append(f"missing {name}")
            elif path.read_text(encoding="utf-8") != text:
                differences.append(f"differs {name}")
        for path in sorted(OUT.glob("*.json")):
            if path.name not in files:
                differences.append(f"unexpected {path.name}")
        if differences:
            print("mcp-auth-security schemas are out of date:", file=sys.stderr)
            for line in differences:
                print(f"  {line}", file=sys.stderr)
            return 1
        print(f"mcp-auth-security schemas are current ({len(files)} schemas)")
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (OUT / name).write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {len(files)} schemas under {OUT.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
