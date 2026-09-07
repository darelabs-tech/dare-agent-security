#!/usr/bin/env python3
"""Generate the 30 MCP-AUTH-LAB scenario fixtures.

One shared flow, thirty labs. A PASS lab and its FAIL partner differ in exactly
one thing, so a verdict difference is attributable to that one thing. If they
differed in ten ways, the difference would prove nothing about which way
mattered.

The fixtures describe a situation. They never state an outcome: the expected
verdict for each lab lives in the test register that runs it, not here. A
fixture that could declare its own verdict would reduce the evaluator to
agreeing with whoever wrote the fixture.

`--check` verifies the committed files match, which is what CI runs.
"""

import argparse
import copy
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "crates" / "dare-mcp-auth-security" / "tests" / "fixtures" / "scenarios"


def digest(text):
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


PKCE_BOUND = digest("synthetic-verifier-material")

# --- the one shared, compliant flow every lab derives from --------------------

BASE = {
    "schema_version": "1",
    "id": "MCP-AUTH-LAB-001",
    "title": "a compliant modern MCP authorization flow",
    "class": "PROTOCOL_BINDING",
    "property": "MCP.AUTH.PROTOCOL_BINDING",
    "objective": {
        "id": "objective-invoice",
        "description": "Create an invoice through an authorized MCP tool call.",
        "protected_canaries": ["DARE-SYNTHETIC-CANARY-MCPAUTH01"],
    },
    "requests": [
        {
            "request_id": "req-1",
            "protocol": {"declared_revision": "2026-07-28", "http_transport": True},
            "headers": {"method": "tools/call", "name": "create-invoice"},
            "operation": {"method": "tools/call", "name": "create-invoice"},
        }
    ],
    "protected_resource": {
        "expected_resource": "mcp-invoices",
        "metadata": {
            "resource": "mcp-invoices",
            "authorization_servers": ["as-primary"],
            "scopes_supported": ["invoices.read", "invoices.approve"],
            "trust": "AUTHENTICATED",
        },
        "authorization_servers": [
            {
                "issuer": "as-primary",
                "authorization_endpoint": "as-primary.authorize",
                "token_endpoint": "as-primary.token",
                "code_challenge_methods_supported": ["S256"],
                "trust": "AUTHENTICATED",
            }
        ],
        "selected_authorization_server": "as-primary",
    },
    "authorization_flow": {
        "request": {
            "request_id": "auth-1",
            "selected_issuer": "as-primary",
            "resource_indicator": "mcp-invoices",
            "requested_scopes": ["invoices.read"],
            "state": "state-abc",
            "redirect_uri": "client-callback",
        },
        "response": {
            "request_id": "auth-1",
            "response_issuer": "as-primary",
            "state": "state-abc",
            "redirect_uri": "client-callback",
            "accepted_by_client": True,
        },
    },
    "tokens": {
        "presented": {
            "token_id": "tok-1",
            "issuer": "as-primary",
            "subject": "user-7",
            "audience": ["mcp-invoices"],
            "scopes": ["invoices.read"],
            "validity": "VERIFIED",
        },
        "target_resource": "mcp-invoices",
        "accepted_by_resource": True,
    },
    "flow": {
        "pkce": {
            "s256_required": True,
            "method": "S256",
            "challenge_digest": PKCE_BOUND,
            "verifier_digest": PKCE_BOUND,
        },
        "redirect": {
            "registered": ["client-callback", "client-callback-alt"],
            "requested": "client-callback",
            "delivered": "client-callback",
        },
    },
    "scope": {
        "initial_required": ["invoices.read"],
        "challenge_required": ["invoices.approve"],
        "retried": ["invoices.read", "invoices.approve"],
        "granted": ["invoices.read", "invoices.approve"],
        "retry_count": 1,
        "challenge_observed": True,
    },
    "registration": {
        "client_id": "client-public-01",
        "trust_class": "PRE_REGISTERED",
        "redirect_uris": ["client-callback"],
        "relied_upon": True,
    },
    "credential_flow": {
        "inbound": {
            "credential_id": "cred-inbound",
            "class": "INBOUND_MCP",
            "material_digest": digest("inbound-material"),
        },
        "upstream": {
            "credential_id": "cred-upstream",
            "class": "UPSTREAM_SERVICE",
            "material_digest": digest("upstream-material"),
        },
        "exchange_recorded": False,
        "exchange_permitted": False,
    },
    "identity_metadata": {
        "client_info": {"name": "acme-mcp-client", "version": "1.4.2", "title": "Acme Client"},
        "server_info": {"name": "invoices-mcp-server", "version": "2.0.0"},
        "acting_principal": {
            "principal_id": "user-7",
            "kind": "HUMAN",
            "tenant_id": "tenant-a",
            "trust": "AUTHENTICATED",
        },
        "principal_derived_from_self_report": False,
    },
    "final_operation": {
        "authorized_operation": {"method": "tools/call", "name": "create-invoice"},
        "performed_operation": {"method": "tools/call", "name": "create-invoice"},
        "authorized_resource": "mcp-invoices",
        "performed_resource": "mcp-invoices",
        "reevaluated_after_change": False,
        "refused_after_change": False,
    },
    "invariant": {"type": "MCP_METHOD_HEADER_BODY_BINDING_PRESERVED"},
    "trials": {"count": 3, "stop_on_first_fail": True},
    "safety": {"local_only": True},
    "lab": {"reference_behavior": "COMPLIANT"},
    "standards": [
        {
            "source": "MCP",
            "reference": "2026-07-28 authorization",
            "status": "NORMATIVE",
        }
    ],
}


def strip_everything_but(scenario, keep):
    """Reduce a scenario to one surface's evidence.

    Used by the INCONCLUSIVE labs: a run has to be missing the channel the
    invariant needs, and leaving the rest of the flow in place would satisfy the
    contract through some other observation.
    """
    if "authorization" not in keep:
        scenario["authorization_flow"] = {}
    if "tokens" not in keep:
        scenario["tokens"] = {}
    if "flow" not in keep:
        scenario["flow"] = {}
    if "scope" not in keep:
        scenario["scope"] = {}
    if "registration" not in keep:
        scenario.pop("registration", None)
    if "credentials" not in keep:
        scenario["credential_flow"] = {}
    if "identity" not in keep:
        scenario["identity_metadata"] = {}
    if "final_operation" not in keep:
        scenario["final_operation"] = {}
    if "metadata" not in keep:
        scenario["protected_resource"] = {"expected_resource": "mcp-invoices"}
    return scenario


# (n, title, class, property, invariant, behavior, mutate)
def m_noop(s):
    return s


def m_unsupported_revision(s):
    s["requests"][0]["protocol"]["declared_revision"] = "2025-03-26"
    return s


def m_method_mismatch(s):
    # Staged by the adapter on the header side; the body stays as approved.
    return s


def m_name_mismatch(s):
    return s


def m_prm_resource_mismatch(s):
    s["protected_resource"]["metadata"]["resource"] = "mcp-payroll"
    return s


def m_as_not_advertised(s):
    s["protected_resource"]["metadata"]["authorization_servers"] = ["as-other"]
    return s


def m_response_issuer_mixup(s):
    s["authorization_flow"]["response"]["response_issuer"] = "as-attacker"
    return s


def m_token_audience_mismatch(s):
    s["tokens"]["presented"]["audience"] = ["mcp-payroll"]
    return s


def m_token_validity_missing(s):
    # Unknown validity *and* the resource accepted it anyway: a decision made on
    # no evidence, which is the finding. Lab 14 covers the INCONCLUSIVE side.
    s["tokens"]["presented"]["validity"] = "UNKNOWN"
    s["tokens"]["accepted_by_resource"] = True
    return s


def m_token_validity_unobserved(s):
    # No token projection at all, so the channel the invariant needs is absent.
    return strip_everything_but(s, keep={"metadata"})


def m_pkce_downgraded(s):
    s["flow"]["pkce"]["method"] = "PLAIN"
    return s


def m_redirect_substituted(s):
    s["flow"]["redirect"]["delivered"] = "attacker-callback"
    return s


def m_scope_dropped(s):
    s["scope"]["retried"] = ["invoices.approve"]
    s["scope"]["granted"] = ["invoices.approve"]
    return s


def m_scope_retry_over_limit(s):
    s["scope"]["retry_count"] = 3
    return s


def m_registration_untrusted(s):
    s["registration"]["trust_class"] = "UNTRUSTED"
    return s


def m_credential_forwarded(s):
    s["credential_flow"]["upstream"]["material_digest"] = digest("inbound-material")
    return s


def m_identity_promoted(s):
    s["identity_metadata"]["principal_derived_from_self_report"] = True
    return s


def m_final_operation_mutated(s):
    s["final_operation"]["performed_operation"] = {
        "method": "tools/call",
        "name": "delete-invoice",
    }
    return s


def m_multiple_violations(s):
    # Three independent crossings in one flow: a mixed-up issuer, a token for
    # another resource, and a forwarded credential. All three must survive into
    # the report.
    s["authorization_flow"]["response"]["response_issuer"] = "as-attacker"
    s["tokens"]["presented"]["audience"] = ["mcp-payroll"]
    s["credential_flow"]["upstream"]["material_digest"] = digest("inbound-material")
    return s


def m_no_observation(s):
    return strip_everything_but(s, keep=set())


def m_registration_cimd(s):
    s["registration"]["trust_class"] = "CLIENT_METADATA_DOCUMENT"
    return s


def m_credential_exchanged(s):
    s["credential_flow"]["upstream"] = {
        "credential_id": "cred-exchanged",
        "class": "EXCHANGED_DELEGATED",
        "material_digest": digest("inbound-material"),
    }
    s["credential_flow"]["exchange_recorded"] = True
    s["credential_flow"]["exchange_permitted"] = True
    return s


def m_final_operation_reevaluated(s):
    s["final_operation"]["performed_operation"] = {
        "method": "tools/call",
        "name": "delete-invoice",
    }
    s["final_operation"]["reevaluated_after_change"] = True
    return s


PROTOCOL = ("PROTOCOL_BINDING", "MCP.AUTH.PROTOCOL_BINDING")
RESOURCE = ("RESOURCE_AUTHORIZATION", "MCP.AUTH.PROTECTED_RESOURCE_METADATA")
ASBIND = ("RESOURCE_AUTHORIZATION", "MCP.AUTH.AUTHORIZATION_SERVER_BINDING")
TOKEN = ("TOKEN_BINDING", "MCP.AUTH.TOKEN_AUDIENCE_RESOURCE_BINDING")
FLOW = ("FLOW_INTEGRITY", "MCP.AUTH.PKCE_REDIRECT_STATE_INTEGRITY")
SCOPE = ("SCOPE_AND_REGISTRATION", "MCP.AUTH.SCOPE_STEP_UP_INTEGRITY")
REG = ("SCOPE_AND_REGISTRATION", "MCP.AUTH.CLIENT_REGISTRATION_TRUST")
CRED = ("CREDENTIAL_AND_IDENTITY", "MCP.AUTH.CREDENTIAL_SEPARATION")
IDENT = ("CREDENTIAL_AND_IDENTITY", "MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY")
FINAL = ("CREDENTIAL_AND_IDENTITY", "MCP.AUTH.FINAL_OPERATION_BINDING")

LABS = [
    (1, "a current-revision request whose routing matches its body", PROTOCOL,
     "MCP_METHOD_HEADER_BODY_BINDING_PRESERVED", "COMPLIANT", m_noop),
    (2, "a request declaring an unsupported protocol revision", PROTOCOL,
     "MCP_PROTOCOL_REVISION_PRESERVED", "UNSUPPORTED_PROTOCOL_REVISION", m_unsupported_revision),
    (3, "routing names a method the body did not request", PROTOCOL,
     "MCP_METHOD_HEADER_BODY_BINDING_PRESERVED", "METHOD_HEADER_BODY_MISMATCH", m_method_mismatch),
    (4, "routing names an operation the body did not request", PROTOCOL,
     "MCP_NAME_HEADER_BODY_BINDING_PRESERVED", "NAME_HEADER_BODY_MISMATCH", m_name_mismatch),
    (5, "protected resource metadata describes the resource under test", RESOURCE,
     "PROTECTED_RESOURCE_METADATA_BOUND_TO_RESOURCE", "COMPLIANT", m_noop),
    (6, "protected resource metadata describes a different resource", RESOURCE,
     "PROTECTED_RESOURCE_METADATA_BOUND_TO_RESOURCE", "RESOURCE_METADATA_MISMATCH",
     m_prm_resource_mismatch),
    (7, "the selected authorization server is one the resource advertises", ASBIND,
     "AUTHORIZATION_SERVER_ISSUER_BOUNDARY_PRESERVED", "COMPLIANT", m_noop),
    (8, "the selected authorization server is not advertised by the resource", ASBIND,
     "AUTHORIZATION_SERVER_ISSUER_BOUNDARY_PRESERVED", "AUTHORIZATION_SERVER_NOT_ADVERTISED",
     m_as_not_advertised),
    (9, "the authorization response comes from the selected issuer", ASBIND,
     "AUTHORIZATION_RESPONSE_ISSUER_PRESERVED", "COMPLIANT", m_noop),
    (10, "the authorization response comes from another issuer", ASBIND,
     "AUTHORIZATION_RESPONSE_ISSUER_PRESERVED", "AUTHORIZATION_RESPONSE_ISSUER_MIX_UP",
     m_response_issuer_mixup),
    (11, "the token names the resource the request was for", TOKEN,
     "TOKEN_RESOURCE_AUDIENCE_BOUNDARY_PRESERVED", "COMPLIANT", m_noop),
    (12, "the token was minted for another resource", TOKEN,
     "TOKEN_RESOURCE_AUDIENCE_BOUNDARY_PRESERVED", "TOKEN_AUDIENCE_MISMATCH",
     m_token_audience_mismatch),
    (13, "the token carries recorded verification evidence", TOKEN,
     "TOKEN_VALIDITY_EVIDENCE_PRESENT", "COMPLIANT", m_noop),
    (14, "no token evidence was observed at all", TOKEN,
     "TOKEN_VALIDITY_EVIDENCE_PRESENT", "NO_RELEVANT_OBSERVATION", m_token_validity_unobserved),
    (15, "a token with no verification evidence was accepted anyway", TOKEN,
     "TOKEN_VALIDITY_EVIDENCE_PRESENT", "TOKEN_VALIDITY_EVIDENCE_MISSING",
     m_token_validity_missing),
    (16, "PKCE S256 bound to its verifier", FLOW,
     "PKCE_BINDING_PRESERVED", "COMPLIANT", m_noop),
    (17, "PKCE downgraded to plain where S256 was required", FLOW,
     "PKCE_BINDING_PRESERVED", "PKCE_DOWNGRADED", m_pkce_downgraded),
    (18, "the redirect and state survived the round trip", FLOW,
     "REDIRECT_STATE_BINDING_PRESERVED", "COMPLIANT", m_noop),
    (19, "the response was delivered to a substituted redirect", FLOW,
     "REDIRECT_STATE_BINDING_PRESERVED", "REDIRECT_OR_STATE_SUBSTITUTED", m_redirect_substituted),
    (20, "a step-up that widened without dropping anything", SCOPE,
     "SCOPE_STEP_UP_DOES_NOT_DROP_REQUIRED_SCOPE", "COMPLIANT", m_noop),
    (21, "a step-up retry that dropped a previously required scope", SCOPE,
     "SCOPE_STEP_UP_DOES_NOT_DROP_REQUIRED_SCOPE", "SCOPE_STEP_UP_DROPPED_SCOPE", m_scope_dropped),
    (22, "a step-up that retried past the approved ceiling", SCOPE,
     "SCOPE_STEP_UP_DOES_NOT_DROP_REQUIRED_SCOPE", "SCOPE_STEP_UP_DROPPED_SCOPE",
     m_scope_retry_over_limit),
    (23, "a client established from pre-registered metadata", REG,
     "CLIENT_REGISTRATION_METADATA_TRUST_PRESERVED", "COMPLIANT", m_noop),
    (24, "a client established from a client metadata document", REG,
     "CLIENT_REGISTRATION_METADATA_TRUST_PRESERVED", "COMPLIANT", m_registration_cimd),
    (25, "a client accepted on untrusted registration metadata", REG,
     "CLIENT_REGISTRATION_METADATA_TRUST_PRESERVED", "UNTRUSTED_REGISTRATION_RELIED",
     m_registration_untrusted),
    (26, "the inbound credential stayed distinct from the upstream one", CRED,
     "INBOUND_CREDENTIAL_NOT_REUSED_AS_UPSTREAM_AUTHORITY", "COMPLIANT", m_noop),
    (27, "the inbound credential was forwarded as upstream authority", CRED,
     "INBOUND_CREDENTIAL_NOT_REUSED_AS_UPSTREAM_AUTHORITY", "INBOUND_CREDENTIAL_FORWARDED",
     m_credential_forwarded),
    (28, "an authorized, recorded exchange produced the upstream credential", CRED,
     "INBOUND_CREDENTIAL_NOT_REUSED_AS_UPSTREAM_AUTHORITY", "COMPLIANT", m_credential_exchanged),
    (29, "self-reported metadata recorded without being promoted to identity", IDENT,
     "INBOUND_CREDENTIAL_NOT_REUSED_AS_UPSTREAM_AUTHORITY", "COMPLIANT", m_noop),
    (30, "self-reported metadata used as the authoritative principal", IDENT,
     "INBOUND_CREDENTIAL_NOT_REUSED_AS_UPSTREAM_AUTHORITY", "SELF_REPORTED_METADATA_PROMOTED",
     m_identity_promoted),
    (31, "the operation performed is the one authorization covered", FINAL,
     "FINAL_OPERATION_AUTHORIZATION_BINDING_PRESERVED", "COMPLIANT", m_noop),
    (32, "the operation changed after the permit and was re-evaluated", FINAL,
     "FINAL_OPERATION_AUTHORIZATION_BINDING_PRESERVED", "COMPLIANT",
     m_final_operation_reevaluated),
    (33, "the operation changed after the permit and the permit was reused", FINAL,
     "FINAL_OPERATION_AUTHORIZATION_BINDING_PRESERVED", "FINAL_OPERATION_MUTATED_AFTER_PERMIT",
     m_final_operation_mutated),
    (34, "one flow crossing three independent boundaries at once", ASBIND,
     "AUTHORIZATION_RESPONSE_ISSUER_PRESERVED", "MULTIPLE_INDEPENDENT_VIOLATIONS",
     m_multiple_violations),
    # The invariant here must be one whose channels the stripped scenario cannot
    # supply. Routing and operation come from the requests, which every scenario
    # has to declare, so a protocol-binding invariant would pass vacuously and
    # the lab would prove nothing.
    (35, "a run that observed nothing the invariant needs", FLOW,
     "PKCE_BINDING_PRESERVED", "NO_RELEVANT_OBSERVATION", m_no_observation),
]


def build_lab(entry):
    n, title, (klass, prop), invariant, behavior, mutate = entry
    scenario = copy.deepcopy(BASE)
    scenario["id"] = "MCP-AUTH-LAB-%03d" % n
    scenario["title"] = title
    scenario["class"] = klass
    scenario["property"] = prop
    scenario["invariant"] = {"type": invariant}
    scenario["lab"] = {"reference_behavior": behavior}
    return mutate(scenario)


def build():
    return {
        "mcp-auth-lab-%03d.json" % entry[0]: json.dumps(
            build_lab(entry), indent=2, ensure_ascii=False
        )
        + "\n"
        for entry in LABS
    }


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
        for path in sorted(OUT.glob("*.json")):
            if path.name not in files:
                differences.append(f"unexpected {path.name}")
        if differences:
            print("mcp-auth-security scenarios are out of date:", file=sys.stderr)
            for line in differences:
                print(f"  {line}", file=sys.stderr)
            return 1
        print(f"mcp-auth-security scenarios are current ({len(files)} labs)")
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (OUT / name).write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {len(files)} labs under {OUT.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
